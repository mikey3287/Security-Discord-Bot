import os
import asyncio
import datetime as dt
from typing import Optional, Tuple

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv
import aiomysql

# ------------ Load env ------------
load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")

DB_HOST = os.getenv("DB_HOST")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME", "discord_security")

INTENTS = discord.Intents.default()
INTENTS.guilds = True
INTENTS.members = True        # For timeouts, joins/leaves, etc.
INTENTS.message_content = False  # We count messages without reading content

# ------------ Utility ------------
RESTRICTED_COMMANDS = {
    "shutdown",
    "reset",
    "lockdown",
    "unlockdown",
    "purge",
    "kick",
    "ban",
    "slowmode",
    "allow",
    "antispam",
}

def now_utc() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)

# ------------ Bot ------------
class SecurityBot(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix="!", intents=INTENTS)
        self.db_pool: Optional[aiomysql.Pool] = None
        # lightweight in-memory counters for anti-spam
        self.msg_window = {}  # {(guild_id, user_id): [timestamps]}
        self.antispam_cache = {}  # {guild_id: (enabled, messages, per_seconds, timeout_seconds)}

    async def setup_hook(self):
        # DB pool
        self.db_pool = await aiomysql.create_pool(
            host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD,
            db=DB_NAME, autocommit=True, minsize=1, maxsize=5
        )
        await self._create_tables()
        await self._warm_antispam_cache()

        # Sync app commands
        try:
            await self.tree.sync()
        except Exception as e:
            print(f"Slash sync failed: {e}")

    async def _create_tables(self):
        sqls = [
            """
            CREATE TABLE IF NOT EXISTS guild_allowed_users (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                guild_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                command_name VARCHAR(64) NOT NULL, -- '*' means all restricted commands
                added_by BIGINT NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_allow (guild_id, user_id, command_name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS settings_antispam (
                guild_id BIGINT PRIMARY KEY,
                enabled TINYINT(1) NOT NULL DEFAULT 0,
                messages INT NOT NULL DEFAULT 6,
                per_seconds INT NOT NULL DEFAULT 4,
                timeout_seconds INT NOT NULL DEFAULT 30
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """
        ]
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cur:
                for s in sqls:
                    await cur.execute(s)

    async def _warm_antispam_cache(self):
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT guild_id, enabled, messages, per_seconds, timeout_seconds FROM settings_antispam")
                rows = await cur.fetchall()
        for gid, enabled, messages, per_s, to_s in rows:
            self.antispam_cache[int(gid)] = (bool(enabled), int(messages), int(per_s), int(to_s))

    async def is_allowed(self, interaction: discord.Interaction, command_name: str) -> bool:
        """Server owner, Administrator, Manage Guild, or DB allowlist for `command_name` or '*'."""
        if not interaction.guild or not interaction.user:
            return False

        # Guild owner shortcut
        if interaction.guild.owner_id == interaction.user.id:
            return True

        # Elevated permission shortcut
        member: discord.Member = interaction.user  # type: ignore
        if member.guild_permissions.administrator or member.guild_permissions.manage_guild:
            return True

        # DB check
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT 1 FROM guild_allowed_users
                    WHERE guild_id=%s AND user_id=%s AND (command_name=%s OR command_name='*') LIMIT 1
                    """,
                    (interaction.guild.id, interaction.user.id, command_name.lower())
                )
                row = await cur.fetchone()
                return row is not None

    async def ensure_guild_antispam_row(self, guild_id: int):
        if guild_id in self.antispam_cache:
            return
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT IGNORE INTO settings_antispam (guild_id) VALUES (%s)",
                    (guild_id,)
                )
        self.antispam_cache[guild_id] = (False, 6, 4, 30)

bot = SecurityBot()

# ------------ Event Handlers ------------
@bot.event
async def on_ready():
    activity = discord.Activity(type=discord.ActivityType.watching, name="/help")
    await bot.change_presence(status=discord.Status.online, activity=activity)
    print(f"✅ Logged in as {bot.user} | {len(bot.guilds)} guild(s)")

@bot.event
async def on_guild_join(guild: discord.Guild):
    await bot.ensure_guild_antispam_row(guild.id)

@bot.event
async def on_message(message: discord.Message):
    # Anti-spam counter (works without reading content)
    if message.author.bot or not message.guild:
        return

    guild_id = message.guild.id
    user_id = message.author.id

    await bot.ensure_guild_antispam_row(guild_id)
    enabled, max_msgs, per_seconds, timeout_seconds = bot.antispam_cache.get(guild_id, (False, 6, 4, 30))
    if not enabled:
        return

    now = now_utc().timestamp()
    key = (guild_id, user_id)
    window = bot.msg_window.get(key, [])
    window.append(now)

    # Keep only within window
    cutoff = now - per_seconds
    window = [t for t in window if t >= cutoff]
    bot.msg_window[key] = window

    if len(window) > max_msgs:
        # Timeout the member (requires Members intent and the bot having Mod privileges)
        try:
            member: discord.Member = message.author  # type: ignore
            until = now_utc() + dt.timedelta(seconds=timeout_seconds)
            await member.edit(timed_out_until=until, reason=f"Auto anti-spam: >{max_msgs}/{per_seconds}s")
            await message.channel.send(
                f"⛔ {member.mention} has been timed out for **{timeout_seconds}s** (anti-spam).",
                silent=True
            )
            bot.msg_window[key] = []  # reset after action
        except Exception as e:
            print(f"Anti-spam timeout failed: {e}")

# ------------ Checks ------------
def restricted(command_name: str):
    def check(func):
        async def wrapper(interaction: discord.Interaction, *args, **kwargs):
            allowed = await bot.is_allowed(interaction, command_name)
            if not allowed:
                return await interaction.response.send_message(
                    "❌ You are not allowed to use this command here.", ephemeral=True
                )
            return await func(interaction, *args, **kwargs)
        return wrapper
    return check

# ------------ Helper Actions ------------
async def set_everyone_send_perms(guild: discord.Guild, allow: bool):
    overwrite_key = guild.default_role
    tasks = []
    for ch in guild.channels:
        if isinstance(ch, (discord.TextChannel, discord.ForumChannel, discord.StageChannel, discord.VoiceChannel)):
            ow = ch.overwrites_for(overwrite_key)
            ow.send_messages = True if allow else False
            try:
                tasks.append(ch.set_permissions(overwrite_key, overwrite=ow, reason="Lockdown" if not allow else "Unlockdown"))
            except Exception:
                pass
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

# ------------ Slash Commands ------------
@bot.tree.command(description="Show help for security & moderation commands.")
async def help(interaction: discord.Interaction):
    embed = discord.Embed(title="🛡️ Security Bot — Help", color=0x5865F2)
    embed.add_field(
        name="Admin/Security",
        value=(
            "**/lockdown** — lock all channels\n"
            "**/unlockdown** — unlock all channels\n"
            "**/purge <amount>** — bulk delete messages\n"
            "**/slowmode <seconds> [#channel]** — set slowmode\n"
            "**/kick @user [reason]** — kick user\n"
            "**/ban @user [reason]** — ban user\n"
            "**/shutdown** — log out the bot (this guild only)\n"
            "**/reset** — reload slash commands\n"
        ),
        inline=False
    )
    embed.add_field(
        name="Access Control (DB‑backed)",
        value=(
            "**/allow add @user [command|*]** — permit user for one command or all\n"
            "**/allow remove @user [command|*]** — remove permission\n"
            "**/allow list [command]** — show who is allowed\n"
            "Owners/Admins/Manage Server are always allowed."
        ),
        inline=False
    )
    embed.add_field(
        name="Anti‑Spam",
        value=(
            "**/antispam on|off** — toggle\n"
            "**/antispam config messages per_seconds timeout_seconds** — set thresholds\n"
            "Ex: 6 msgs / 4s → 30s timeout."
        ),
        inline=False
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)

# ---- Access control
@bot.tree.command(name="allow", description="Manage who can run restricted commands (stored in DB).")
@app_commands.describe(
    action="add or remove or list",
    user="User to allow/deny (not required for 'list')",
    command="Command name (e.g., 'shutdown') or '*' for all; optional for 'list'"
)
@app_commands.choices(action=[
    app_commands.Choice(name="add", value="add"),
    app_commands.Choice(name="remove", value="remove"),
    app_commands.Choice(name="list", value="list"),
])
@restricted("allow")
async def allow_cmd(
    interaction: discord.Interaction,
    action: app_commands.Choice[str],
    user: Optional[discord.User] = None,
    command: Optional[str] = None
):
    if not interaction.guild:
        return await interaction.response.send_message("Guild only.", ephemeral=True)

    action_v = action.value
    command_name = (command or "*").lower()

    if action_v in ("add", "remove") and user is None:
        return await interaction.response.send_message("Please select a user.", ephemeral=True)

    if command_name != "*" and command_name not in RESTRICTED_COMMANDS:
        return await interaction.response.send_message(
            f"Unknown command `{command_name}`. Try one of: {', '.join(sorted(RESTRICTED_COMMANDS))} or `*`.",
            ephemeral=True
        )

    async with bot.db_pool.acquire() as conn:
        async with conn.cursor() as cur:
            if action_v == "add":
                await cur.execute(
                    """
                    INSERT IGNORE INTO guild_allowed_users (guild_id, user_id, command_name, added_by)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (interaction.guild.id, user.id, command_name, interaction.user.id)
                )
                await interaction.response.send_message(f"✅ {user.mention} is now allowed to use `{command_name}`.", ephemeral=True)

            elif action_v == "remove":
                await cur.execute(
                    """
                    DELETE FROM guild_allowed_users
                    WHERE guild_id=%s AND user_id=%s AND command_name=%s
                    """,
                    (interaction.guild.id, user.id, command_name)
                )
                await interaction.response.send_message(f"🗑️ Removed permission `{command_name}` from {user.mention}.", ephemeral=True)

            elif action_v == "list":
                if command_name == "*":
                    await cur.execute(
                        "SELECT user_id, command_name FROM guild_allowed_users WHERE guild_id=%s ORDER BY user_id",
                        (interaction.guild.id,)
                    )
                else:
                    await cur.execute(
                        "SELECT user_id, command_name FROM guild_allowed_users WHERE guild_id=%s AND (command_name=%s OR command_name='*') ORDER BY user_id",
                        (interaction.guild.id, command_name)
                    )
                rows = await cur.fetchall()
                if not rows:
                    return await interaction.response.send_message("No entries.", ephemeral=True)
                lines = []
                for uid, cmd in rows:
                    lines.append(f"<@{uid}> — `{cmd}`")
                await interaction.response.send_message("**Allowed users:**\n" + "\n".join(lines), ephemeral=True)

# ---- Core security
@bot.tree.command(description="Lock all channels for @everyone.")
@restricted("lockdown")
async def lockdown(interaction: discord.Interaction):
    if not interaction.guild:
        return await interaction.response.send_message("Guild only.", ephemeral=True)
    await interaction.response.send_message("🔒 Locking all channels…", ephemeral=True)
    await set_everyone_send_perms(interaction.guild, allow=False)
    await interaction.followup.send("✅ Lockdown enabled. Only roles with overrides can speak.", ephemeral=True)

@bot.tree.command(description="Unlock all channels for @everyone.")
@restricted("unlockdown")
async def unlockdown(interaction: discord.Interaction):
    if not interaction.guild:
        return await interaction.response.send_message("Guild only.", ephemeral=True)
    await interaction.response.send_message("🔓 Unlocking all channels…", ephemeral=True)
    await set_everyone_send_perms(interaction.guild, allow=True)
    await interaction.followup.send("✅ Lockdown disabled.", ephemeral=True)

@bot.tree.command(description="Bulk delete a number of recent messages.")
@app_commands.describe(amount="How many messages to delete (max 200).")
@restricted("purge")
async def purge(interaction: discord.Interaction, amount: app_commands.Range[int, 1, 200]):
    channel = interaction.channel
    if not isinstance(channel, discord.TextChannel):
        return await interaction.response.send_message("Use in a text channel.", ephemeral=True)
    await interaction.response.send_message(f"🧹 Deleting {amount} messages…", ephemeral=True)
    deleted = await channel.purge(limit=amount)
    await interaction.followup.send(f"✅ Deleted {len(deleted)} messages.", ephemeral=True)

@bot.tree.command(description="Set slowmode on a channel.")
@app_commands.describe(seconds="Slowmode seconds (0 to disable).", channel="Target channel (defaults to current).")
@restricted("slowmode")
async def slowmode(interaction: discord.Interaction, seconds: app_commands.Range[int, 0, 21600], channel: Optional[discord.TextChannel] = None):
    channel = channel or interaction.channel
    if not isinstance(channel, discord.TextChannel):
        return await interaction.response.send_message("Pick a text channel.", ephemeral=True)
    await channel.edit(slowmode_delay=seconds, reason=f"Set by {interaction.user}")
    await interaction.response.send_message(f"🐢 Slowmode set to **{seconds}s** for {channel.mention}.", ephemeral=True)

@bot.tree.command(description="Kick a user.")
@app_commands.describe(user="User to kick", reason="Reason (optional)")
@restricted("kick")
async def kick(interaction: discord.Interaction, user: discord.Member, reason: Optional[str] = None):
    await user.kick(reason=reason or f"Kick by {interaction.user}")
    await interaction.response.send_message(f"👢 Kicked {user.mention}.", ephemeral=True)

@bot.tree.command(description="Ban a user.")
@app_commands.describe(user="User to ban", reason="Reason (optional)")
@restricted("ban")
async def ban(interaction: discord.Interaction, user: discord.Member, reason: Optional[str] = None):
    await user.ban(reason=reason or f"Ban by {interaction.user}")
    await interaction.response.send_message(f"🔨 Banned {user.mention}.", ephemeral=True)

# ---- Anti-spam config
@bot.tree.command(description="Enable or disable anti-spam.")
@app_commands.describe(state="on or off")
@app_commands.choices(state=[
    app_commands.Choice(name="on", value="on"),
    app_commands.Choice(name="off", value="off"),
])
@restricted("antispam")
async def antispam(interaction: discord.Interaction, state: app_commands.Choice[str]):
    if not interaction.guild:
        return await interaction.response.send_message("Guild only.", ephemeral=True)
    enabled = (state.value == "on")
    async with bot.db_pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO settings_antispam (guild_id, enabled) VALUES (%s, %s) ON DUPLICATE KEY UPDATE enabled=VALUES(enabled)",
                (interaction.guild.id, int(enabled))
            )
    bot.antispam_cache[interaction.guild.id] = (enabled, *bot.antispam_cache.get(interaction.guild.id, (False, 6, 4, 30))[1:])
    await interaction.response.send_message(f"✅ Anti‑spam **{'enabled' if enabled else 'disabled'}**.", ephemeral=True)

@bot.tree.command(description="Configure anti-spam thresholds.")
@app_commands.describe(
    messages="Max messages within the window (e.g., 6)",
    per_seconds="Window length in seconds (e.g., 4)",
    timeout_seconds="Timeout length in seconds (e.g., 30)",
)
@restricted("antispam")
async def antispam_config(interaction: discord.Interaction, messages: app_commands.Range[int, 2, 30], per_seconds: app_commands.Range[int, 2, 30], timeout_seconds: app_commands.Range[int, 5, 600]):
    if not interaction.guild:
        return await interaction.response.send_message("Guild only.", ephemeral=True)
    async with bot.db_pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO settings_antispam (guild_id, enabled, messages, per_seconds, timeout_seconds)
                VALUES (%s, 1, %s, %s, %s)
                ON DUPLICATE KEY UPDATE messages=VALUES(messages), per_seconds=VALUES(per_seconds), timeout_seconds=VALUES(timeout_seconds)
                """,
                (interaction.guild.id, messages, per_seconds, timeout_seconds)
            )
    bot.antispam_cache[interaction.guild.id] = (True, messages, per_seconds, timeout_seconds)
    await interaction.response.send_message(f"🔧 Anti‑spam set to **{messages}/{per_seconds}s → {timeout_seconds}s timeout**.", ephemeral=True)

# ---- Maintenance
@bot.tree.command(description="Reload slash commands for this bot.")
@restricted("reset")
async def reset(interaction: discord.Interaction):
    try:
        await bot.tree.sync()
        await interaction.response.send_message("🔁 Commands reloaded.", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"❌ Failed: {e}", ephemeral=True)

@bot.tree.command(description="Shut down the bot (this process).")
@restricted("shutdown")
async def shutdown(interaction: discord.Interaction):
    await interaction.response.send_message("🛑 Shutting down…", ephemeral=True)
    await bot.close()

# ------------ Run ------------
if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("DISCORD_TOKEN missing in .env")
    if not all([DB_HOST, DB_USER, DB_PASSWORD, DB_NAME]):
        raise SystemExit("DB env vars missing. Check .env.")
    bot.run(TOKEN)
