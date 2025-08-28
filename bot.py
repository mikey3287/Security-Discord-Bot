# bot.py
import os
import ssl
import asyncio
import datetime as dt
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv
import aiomysql

# Theme/config (edit in config.py)
from config import (
    EMBED_COLOR, SUCCESS_COLOR, ERROR_COLOR, WARNING_COLOR,
    FOOTER_TEXT, FOOTER_ICON
)

# ===================== ENV & INTENTS =====================
load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")

DB_HOST = os.getenv("DB_HOST")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME", "discord_security")

# Optional SSL for hosts that require it (0/1)
DB_SSL = int(os.getenv("DB_SSL", "0"))                 # 1 to enable SSL
DB_SSL_VERIFY = int(os.getenv("DB_SSL_VERIFY", "0"))   # 1 to verify certs

INTENTS = discord.Intents.default()
INTENTS.guilds = True
INTENTS.members = False          # needed for timeouts, kicks, bans
INTENTS.message_content = False # we don't need content for anti-spam

# Commands that require allowlist/privilege
RESTRICTED_COMMANDS = {
    "shutdown",
    "reset",
    "lockdown",
    "unlockdown",
    "purge",
    "slowmode",
    "kick",
    "ban",
    "allow",
    "antispam",
}

def now_utc() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)

# ===================== BOT CLASS =====================
class SecurityBot(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix="!", intents=INTENTS)
        self.db_pool: Optional[aiomysql.Pool] = None

        # anti-spam runtime state
        self.msg_window: dict[tuple[int, int], list[float]] = {}
        # guild_id -> (enabled, messages, per_seconds, timeout_seconds)
        self.antispam_cache: dict[int, tuple[bool, int, int, int]] = {}

    async def setup_hook(self):
        # Validate env early
        missing = [k for k, v in {
            "DISCORD_TOKEN": TOKEN, "DB_HOST": DB_HOST, "DB_USER": DB_USER,
            "DB_PASSWORD": DB_PASSWORD, "DB_NAME": DB_NAME
        }.items() if not v]
        if missing:
            raise SystemExit(f"Missing env vars: {', '.join(missing)}")

        # Optional SSL context
        ssl_ctx = None
        if DB_SSL:
            ssl_ctx = ssl.create_default_context()
            if not DB_SSL_VERIFY:
                # Looser for hosts without proper CA chain; enable verify once possible
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

        # Connect DB pool (with timeout and recycle to avoid stale connections)
        try:
            self.db_pool = await aiomysql.create_pool(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                db=DB_NAME,
                autocommit=True,
                minsize=1,
                maxsize=5,
                connect_timeout=10,   # quicker failure if unreachable
                ssl=ssl_ctx,          # None unless DB_SSL=1
                pool_recycle=1800,    # recycle every 30m
            )
        except Exception as e:
            raise SystemExit(
                f"❌ Could not connect to DB at {DB_HOST}:{DB_PORT} as {DB_USER}. "
                f"Error: {type(e).__name__}: {e}\n"
                f"Tip: Check if remote connections are allowed, host/port are correct, "
                f"and whether SSL is needed (set DB_SSL=1)."
            )

        await self._create_tables()
        await self._warm_antispam_cache()

        # Sync slash commands
        try:
            await self.tree.sync()
        except Exception as e:
            print(f"[WARN] Slash sync failed: {e}")

    async def _create_tables(self):
        sqls = [
            """
            CREATE TABLE IF NOT EXISTS guild_allowed_users (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                guild_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                command_name VARCHAR(64) NOT NULL, -- '*' = all restricted commands
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
            """,
        ]
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cur:
                for s in sqls:
                    await cur.execute(s)

    async def _warm_antispam_cache(self):
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT guild_id, enabled, messages, per_seconds, timeout_seconds FROM settings_antispam"
                )
                rows = await cur.fetchall()
        for gid, enabled, msgs, per_s, to_s in rows:
            self.antispam_cache[int(gid)] = (bool(enabled), int(msgs), int(per_s), int(to_s))

    async def ensure_guild_antispam_row(self, guild_id: int):
        if guild_id in self.antispam_cache:
            return
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT IGNORE INTO settings_antispam (guild_id) VALUES (%s)",
                    (guild_id,),
                )
        self.antispam_cache[guild_id] = (False, 6, 4, 30)

    async def is_allowed(self, interaction: discord.Interaction, command_name: str) -> bool:
        """Owner/Admin/Manage Guild OR allowlisted in DB for command or '*'."""
        if not interaction.guild or not interaction.user:
            return False

        # Owner always allowed
        if interaction.guild.owner_id == interaction.user.id:
            return True

        # Elevated perms allowed
        member: discord.Member = interaction.user  # type: ignore
        if member.guild_permissions.administrator or member.guild_permissions.manage_guild:
            return True

        # DB allowlist
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT 1
                    FROM guild_allowed_users
                    WHERE guild_id=%s AND user_id=%s AND (command_name=%s OR command_name='*')
                    LIMIT 1
                    """,
                    (interaction.guild.id, interaction.user.id, command_name.lower()),
                )
                row = await cur.fetchone()
                return row is not None

bot = SecurityBot()

# ===================== CHECK DECORATOR FOR SLASH =====================
def require_allowed(command_name: str):
    async def predicate(interaction: discord.Interaction) -> bool:
        allowed = await bot.is_allowed(interaction, command_name)
        if allowed:
            return True
        # Nice error embed
        embed = discord.Embed(
            description="❌ You are not allowed to use this command here.",
            color=ERROR_COLOR
        )
        embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
        try:
            await interaction.response.send_message(embed=embed, ephemeral=True)
        except discord.InteractionResponded:
            await interaction.followup.send(embed=embed, ephemeral=True)
        return False
    return app_commands.check(predicate)

# ===================== EVENTS =====================
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
    # anti-spam without reading content
    if message.author.bot or not message.guild:
        return

    gid = message.guild.id
    uid = message.author.id
    await bot.ensure_guild_antispam_row(gid)
    enabled, max_msgs, per_seconds, timeout_seconds = bot.antispam_cache.get(gid, (False, 6, 4, 30))
    if not enabled:
        return

    now = now_utc().timestamp()
    key = (gid, uid)
    window = bot.msg_window.get(key, [])
    window.append(now)
    # keep only recent
    cutoff = now - per_seconds
    window = [t for t in window if t >= cutoff]
    bot.msg_window[key] = window

    if len(window) > max_msgs:
        try:
            member: discord.Member = message.author  # type: ignore
            until = now_utc() + dt.timedelta(seconds=timeout_seconds)
            await member.edit(timed_out_until=until, reason=f"Auto anti-spam: >{max_msgs}/{per_seconds}s")

            embed = discord.Embed(
                description=f"⛔ {member.mention} has been timed out for **{timeout_seconds}s** (anti-spam).",
                color=WARNING_COLOR
            )
            embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
            await message.channel.send(embed=embed, silent=True)

            bot.msg_window[key] = []
        except Exception as e:
            print(f"[WARN] Anti-spam timeout failed: {e}")

# ===================== HELPERS =====================
async def set_everyone_send_perms(guild: discord.Guild, allow: bool):
    overwrite_key = guild.default_role
    tasks: list[asyncio.Task] = []
    for ch in guild.channels:
        if isinstance(ch, (discord.TextChannel, discord.ForumChannel, discord.StageChannel, discord.VoiceChannel)):
            ow = ch.overwrites_for(overwrite_key)
            ow.send_messages = True if allow else False
            try:
                tasks.append(asyncio.create_task(
                    ch.set_permissions(overwrite_key, overwrite=ow, reason="Lockdown" if not allow else "Unlockdown")
                ))
            except Exception:
                pass
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

# ===================== SLASH COMMANDS =====================
@bot.tree.command(description="Show help for security & moderation commands.")
async def help(interaction: discord.Interaction):
    embed = discord.Embed(title="🛡️ Security Bot — Help", color=EMBED_COLOR)
    embed.add_field(
        name="Admin/Security",
        value=(
            "**/lockdown** — lock all channels\n"
            "**/unlockdown** — unlock all channels\n"
            "**/purge <amount>** — bulk delete messages\n"
            "**/slowmode <seconds> [#channel]** — set slowmode\n"
            "**/kick @user [reason]** — kick user\n"
            "**/ban @user [reason]** — ban user\n"
            "**/shutdown** — stop the bot process\n"
            "**/reset** — reload slash commands\n"
        ),
        inline=False,
    )
    embed.add_field(
        name="Access Control (DB-backed)",
        value=(
            "**/allow add @user [command|*]** — permit user for one or all restricted commands\n"
            "**/allow remove @user [command|*]** — remove permission\n"
            "**/allow list [command]** — list who is allowed\n"
            "Owner/Admin/Manage Server are always allowed."
        ),
        inline=False,
    )
    embed.add_field(
        name="Anti-Spam",
        value=(
            "**/antispam on|off** — toggle\n"
            "**/antispam_config messages per_seconds timeout_seconds** — thresholds\n"
            "Example: 6 msgs / 4s → 30s timeout."
        ),
        inline=False,
    )
    embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
    await interaction.response.send_message(embed=embed, ephemeral=True)

# ---- Access Control
@bot.tree.command(name="allow", description="Manage who can run restricted commands (stored in DB).")
@app_commands.describe(
    action="add or remove or list",
    user="User to allow/deny (not required for 'list')",
    command="Command name (e.g., 'shutdown') or '*' for all; optional for 'list'",
)
@app_commands.choices(action=[
    app_commands.Choice(name="add", value="add"),
    app_commands.Choice(name="remove", value="remove"),
    app_commands.Choice(name="list", value="list"),
])
@require_allowed("allow")
async def allow_cmd(
    interaction: discord.Interaction,
    action: app_commands.Choice[str],
    user: Optional[discord.User] = None,
    command: Optional[str] = None,
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
            ephemeral=True,
        )

    assert bot.db_pool is not None
    async with bot.db_pool.acquire() as conn:
        async with conn.cursor() as cur:
            if action_v == "add":
                await cur.execute(
                    """
                    INSERT IGNORE INTO guild_allowed_users (guild_id, user_id, command_name, added_by)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (interaction.guild.id, user.id, command_name, interaction.user.id),
                )
                embed = discord.Embed(
                    description=f"✅ {user.mention} is now allowed to use `{command_name}`.",
                    color=SUCCESS_COLOR
                )
                embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
                return await interaction.response.send_message(embed=embed, ephemeral=True)

            if action_v == "remove":
                await cur.execute(
                    """
                    DELETE FROM guild_allowed_users
                    WHERE guild_id=%s AND user_id=%s AND command_name=%s
                    """,
                    (interaction.guild.id, user.id, command_name),
                )
                embed = discord.Embed(
                    description=f"🗑️ Removed permission `{command_name}` from {user.mention}.",
                    color=WARNING_COLOR
                )
                embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
                return await interaction.response.send_message(embed=embed, ephemeral=True)

            # list
            if command_name == "*":
                await cur.execute(
                    "SELECT user_id, command_name FROM guild_allowed_users WHERE guild_id=%s ORDER BY user_id",
                    (interaction.guild.id,),
                )
            else:
                await cur.execute(
                    """
                    SELECT user_id, command_name
                    FROM guild_allowed_users
                    WHERE guild_id=%s AND (command_name=%s OR command_name='*')
                    ORDER BY user_id
                    """,
                    (interaction.guild.id, command_name),
                )
            rows = await cur.fetchall()
            if not rows:
                return await interaction.response.send_message("No entries.", ephemeral=True)
            lines = [f"<@{uid}> — `{cmd}`" for uid, cmd in rows]

            embed = discord.Embed(
                title="Allowed Users",
                description="\n".join(lines),
                color=EMBED_COLOR
            )
            embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
            await interaction.response.send_message(embed=embed, ephemeral=True)

# ---- Security / Moderation
@bot.tree.command(description="Lock all channels for @everyone.")
@require_allowed("lockdown")
async def lockdown(interaction: discord.Interaction):
    if not interaction.guild:
        return await interaction.response.send_message("Guild only.", ephemeral=True)
    await interaction.response.send_message("🔒 Locking all channels…", ephemeral=True)
    await set_everyone_send_perms(interaction.guild, allow=False)
    embed = discord.Embed(
        description="✅ Lockdown enabled. Only roles with explicit overrides can speak.",
        color=SUCCESS_COLOR
    )
    embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(description="Unlock all channels for @everyone.")
@require_allowed("unlockdown")
async def unlockdown(interaction: discord.Interaction):
    if not interaction.guild:
        return await interaction.response.send_message("Guild only.", ephemeral=True)
    await interaction.response.send_message("🔓 Unlocking all channels…", ephemeral=True)
    await set_everyone_send_perms(interaction.guild, allow=True)
    embed = discord.Embed(
        description="✅ Lockdown disabled.",
        color=SUCCESS_COLOR
    )
    embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(description="Bulk delete a number of recent messages.")
@app_commands.describe(amount="How many messages to delete (max 200).")
@require_allowed("purge")
async def purge(interaction: discord.Interaction, amount: app_commands.Range[int, 1, 200]):
    channel = interaction.channel
    if not isinstance(channel, discord.TextChannel):
        return await interaction.response.send_message("Use in a text channel.", ephemeral=True)
    await interaction.response.send_message(f"🧹 Deleting {amount} messages…", ephemeral=True)
    deleted = await channel.purge(limit=amount)
    embed = discord.Embed(
        description=f"✅ Deleted {len(deleted)} messages.",
        color=SUCCESS_COLOR
    )
    embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(description="Set slowmode on a channel.")
@app_commands.describe(
    seconds="Slowmode seconds (0 to disable).",
    channel="Target channel (defaults to current).",
)
@require_allowed("slowmode")
async def slowmode(
    interaction: discord.Interaction,
    seconds: app_commands.Range[int, 0, 21600],
    channel: Optional[discord.TextChannel] = None,
):
    target = channel or interaction.channel
    if not isinstance(target, discord.TextChannel):
        return await interaction.response.send_message("Pick a text channel.", ephemeral=True)
    await target.edit(slowmode_delay=seconds, reason=f"Set by {interaction.user}")
    embed = discord.Embed(
        description=f"🐢 Slowmode set to **{seconds}s** for {target.mention}.",
        color=SUCCESS_COLOR
    )
    embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(description="Kick a user.")
@app_commands.describe(user="User to kick", reason="Reason (optional)")
@require_allowed("kick")
async def kick(interaction: discord.Interaction, user: discord.Member, reason: Optional[str] = None):
    await user.kick(reason=reason or f"Kick by {interaction.user}")
    embed = discord.Embed(
        description=f"👢 Kicked {user.mention}.",
        color=SUCCESS_COLOR
    )
    embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(description="Ban a user.")
@app_commands.describe(user="User to ban", reason="Reason (optional)")
@require_allowed("ban")
async def ban(interaction: discord.Interaction, user: discord.Member, reason: Optional[str] = None):
    await user.ban(reason=reason or f"Ban by {interaction.user}")
    embed = discord.Embed(
        description=f"🔨 Banned {user.mention}.",
        color=SUCCESS_COLOR
    )
    embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
    await interaction.response.send_message(embed=embed, ephemeral=True)

# ---- Anti-spam config
@bot.tree.command(description="Enable or disable anti-spam.")
@app_commands.describe(state="on or off")
@app_commands.choices(state=[
    app_commands.Choice(name="on", value="on"),
    app_commands.Choice(name="off", value="off"),
])
@require_allowed("antispam")
async def antispam(interaction: discord.Interaction, state: app_commands.Choice[str]):
    if not interaction.guild:
        return await interaction.response.send_message("Guild only.", ephemeral=True)
    enabled = (state.value == "on")
    assert bot.db_pool is not None
    async with bot.db_pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO settings_antispam (guild_id, enabled)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE enabled=VALUES(enabled)
                """,
                (interaction.guild.id, int(enabled)),
            )
    # keep cache in sync
    prev = bot.antispam_cache.get(interaction.guild.id, (False, 6, 4, 30))
    bot.antispam_cache[interaction.guild.id] = (enabled, prev[1], prev[2], prev[3])
    color = SUCCESS_COLOR if enabled else WARNING_COLOR
    embed = discord.Embed(
        description=f"✅ Anti-spam **{'enabled' if enabled else 'disabled'}**.",
        color=color
    )
    embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="antispam_config", description="Configure anti-spam thresholds.")
@app_commands.describe(
    messages="Max messages within the window (e.g., 6)",
    per_seconds="Window length in seconds (e.g., 4)",
    timeout_seconds="Timeout length in seconds (e.g., 30)",
)
@require_allowed("antispam")
async def antispam_config(
    interaction: discord.Interaction,
    messages: app_commands.Range[int, 2, 30],
    per_seconds: app_commands.Range[int, 2, 30],
    timeout_seconds: app_commands.Range[int, 5, 600],
):
    if not interaction.guild:
        return await interaction.response.send_message("Guild only.", ephemeral=True)
    assert bot.db_pool is not None
    async with bot.db_pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO settings_antispam (guild_id, enabled, messages, per_seconds, timeout_seconds)
                VALUES (%s, 1, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    messages=VALUES(messages),
                    per_seconds=VALUES(per_seconds),
                    timeout_seconds=VALUES(timeout_seconds),
                    enabled=1
                """,
                (interaction.guild.id, messages, per_seconds, timeout_seconds),
            )
    bot.antispam_cache[interaction.guild.id] = (True, int(messages), int(per_seconds), int(timeout_seconds))
    embed = discord.Embed(
        description=f"🔧 Anti-spam set to **{messages}/{per_seconds}s → {timeout_seconds}s timeout**.",
        color=SUCCESS_COLOR
    )
    embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
    await interaction.response.send_message(embed=embed, ephemeral=True)

# ---- Maintenance
@bot.tree.command(description="Reload slash commands for this bot.")
@require_allowed("reset")
async def reset(interaction: discord.Interaction):
    try:
        await bot.tree.sync()
        embed = discord.Embed(description="🔁 Commands reloaded.", color=SUCCESS_COLOR)
        embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
        await interaction.response.send_message(embed=embed, ephemeral=True)
    except Exception as e:
        embed = discord.Embed(description=f"❌ Failed: {e}", color=ERROR_COLOR)
        embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
        await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(description="Shut down the bot (this process).")
@require_allowed("shutdown")
async def shutdown(interaction: discord.Interaction):
    embed = discord.Embed(description="🛑 Shutting down…", color=WARNING_COLOR)
    embed.set_footer(text=FOOTER_TEXT, icon_url=FOOTER_ICON)
    await interaction.response.send_message(embed=embed, ephemeral=True)
    await bot.close()


# ===================== RUN =====================
if __name__ == "__main__":
    bot.run(TOKEN)


@bot.event
async def on_ready():
    activity = discord.Activity(type=discord.ActivityType.watching, name="/help")
    await bot.change_presence(status=discord.Status.online, activity=activity)
    print(f"✅ Logged in as {bot.user} | {len(bot.guilds)} guild(s)")
   
