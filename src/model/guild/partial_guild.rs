use nonmax::{NonMaxU16, NonMaxU64, NonMaxU8};
use serde::Serialize;

#[cfg(feature = "model")]
use crate::builder::{
    CreateChannel,
    CreateCommand,
    CreateSticker,
    EditAutoModRule,
    EditCommandPermissions,
    EditGuild,
    EditGuildWelcomeScreen,
    EditGuildWidget,
    EditMember,
    EditRole,
    EditSticker,
};
#[cfg(feature = "collector")]
use crate::collector::{MessageCollector, ReactionCollector};
#[cfg(feature = "collector")]
use crate::gateway::ShardMessenger;
#[cfg(feature = "model")]
use crate::http::{CacheHttp, Http, UserPagination};
use crate::internal::prelude::*;
use crate::internal::utils::lending_for_each;
use crate::model::prelude::*;
#[cfg(feature = "model")]
use crate::model::utils::icon_url;

/// Partial information about a [`Guild`]. This does not include information like member data.
///
/// [Discord docs](https://discord.com/developers/docs/resources/guild#guild-object).
#[bool_to_bitflags::bool_to_bitflags]
#[cfg_attr(feature = "typesize", derive(typesize::derive::TypeSize))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(remote = "Self")]
#[non_exhaustive]
pub struct PartialGuild {
    // ======
    // These fields are copy-pasted from the top part of Guild, and the omitted fields filled in
    // ======
    /// The unique Id identifying the guild.
    ///
    /// This is equivalent to the Id of the default role (`@everyone`).
    pub id: GuildId,
    /// The name of the guild.
    pub name: FixedString,
    /// The hash of the icon used by the guild.
    ///
    /// In the client, this appears on the guild list on the left-hand side.
    pub icon: Option<ImageHash>,
    /// Icon hash, returned when in the template object
    pub icon_hash: Option<ImageHash>,
    /// An identifying hash of the guild's splash icon.
    ///
    /// If the `InviteSplash` feature is enabled, this can be used to generate a URL to a splash
    /// image.
    pub splash: Option<ImageHash>,
    /// An identifying hash of the guild discovery's splash icon.
    ///
    /// **Note**: Only present for guilds with the `DISCOVERABLE` feature.
    pub discovery_splash: Option<ImageHash>,
    // Omitted `owner` field because only Http::get_guilds uses it, which returns GuildInfo
    /// The Id of the [`User`] who owns the guild.
    pub owner_id: UserId,
    // Omitted `permissions` field because only Http::get_guilds uses it, which returns GuildInfo
    // Omitted `region` field because it is deprecated (see Discord docs)
    /// Information about the voice afk channel.
    #[serde(flatten)]
    pub afk_metadata: Option<AfkMetadata>,
    /// Whether or not the guild widget is enabled.
    pub widget_enabled: Option<bool>,
    /// The channel id that the widget will generate an invite to, or null if set to no invite
    pub widget_channel_id: Option<ChannelId>,
    /// Indicator of the current verification level of the guild.
    pub verification_level: VerificationLevel,
    /// Indicator of whether notifications for all messages are enabled by
    /// default in the guild.
    pub default_message_notifications: DefaultMessageNotificationLevel,
    /// Default explicit content filter level.
    pub explicit_content_filter: ExplicitContentFilter,
    /// A mapping of the guild's roles.
    pub roles: ExtractMap<RoleId, Role>,
    /// All of the guild's custom emojis.
    pub emojis: ExtractMap<EmojiId, Emoji>,
    /// The guild features. More information available at [`discord documentation`].
    ///
    /// The following is a list of known features:
    /// - `ANIMATED_ICON`
    /// - `BANNER`
    /// - `COMMERCE`
    /// - `COMMUNITY`
    /// - `DISCOVERABLE`
    /// - `FEATURABLE`
    /// - `INVITE_SPLASH`
    /// - `MEMBER_VERIFICATION_GATE_ENABLED`
    /// - `MONETIZATION_ENABLED`
    /// - `MORE_STICKERS`
    /// - `NEWS`
    /// - `PARTNERED`
    /// - `PREVIEW_ENABLED`
    /// - `PRIVATE_THREADS`
    /// - `ROLE_ICONS`
    /// - `SEVEN_DAY_THREAD_ARCHIVE`
    /// - `THREE_DAY_THREAD_ARCHIVE`
    /// - `TICKETED_EVENTS_ENABLED`
    /// - `VANITY_URL`
    /// - `VERIFIED`
    /// - `VIP_REGIONS`
    /// - `WELCOME_SCREEN_ENABLED`
    /// - `THREE_DAY_THREAD_ARCHIVE`
    /// - `SEVEN_DAY_THREAD_ARCHIVE`
    /// - `PRIVATE_THREADS`
    ///
    ///
    /// [`discord documentation`]: https://discord.com/developers/docs/resources/guild#guild-object-guild-features
    pub features: FixedArray<FixedString>,
    /// Indicator of whether the guild requires multi-factor authentication for [`Role`]s or
    /// [`User`]s with moderation permissions.
    pub mfa_level: MfaLevel,
    /// Application ID of the guild creator if it is bot-created.
    pub application_id: Option<ApplicationId>,
    /// The ID of the channel to which system messages are sent.
    pub system_channel_id: Option<ChannelId>,
    /// System channel flags.
    pub system_channel_flags: SystemChannelFlags,
    /// The id of the channel where rules and/or guidelines are displayed.
    ///
    /// **Note**: Only available on `COMMUNITY` guild, see [`Self::features`].
    pub rules_channel_id: Option<ChannelId>,
    /// The maximum number of presences for the guild. The default value is currently 25000.
    ///
    /// **Note**: It is in effect when it is `None`.
    pub max_presences: Option<NonMaxU64>,
    /// The maximum number of members for the guild.
    pub max_members: Option<NonMaxU64>,
    /// The vanity url code for the guild, if it has one.
    pub vanity_url_code: Option<FixedString>,
    /// The server's description, if it has one.
    pub description: Option<FixedString>,
    /// The guild's banner, if it has one.
    pub banner: Option<FixedString>,
    /// The server's premium boosting level.
    pub premium_tier: PremiumTier,
    /// The total number of users currently boosting this server.
    pub premium_subscription_count: Option<NonMaxU64>,
    /// The preferred locale of this guild only set if guild has the "DISCOVERABLE" feature,
    /// defaults to en-US.
    pub preferred_locale: FixedString,
    /// The id of the channel where admins and moderators of Community guilds receive notices from
    /// Discord.
    ///
    /// **Note**: Only available on `COMMUNITY` guild, see [`Self::features`].
    pub public_updates_channel_id: Option<ChannelId>,
    /// The maximum amount of users in a video channel.
    pub max_video_channel_users: Option<NonMaxU64>,
    /// The maximum amount of users in a stage video channel
    pub max_stage_video_channel_users: Option<NonMaxU64>,
    /// Approximate number of members in this guild.
    pub approximate_member_count: Option<NonMaxU64>,
    /// Approximate number of non-offline members in this guild.
    pub approximate_presence_count: Option<NonMaxU64>,
    /// The welcome screen of the guild.
    ///
    /// **Note**: Only available on `COMMUNITY` guild, see [`Self::features`].
    pub welcome_screen: Option<GuildWelcomeScreen>,
    /// The guild NSFW state. See [`discord support article`].
    ///
    /// [`discord support article`]: https://support.discord.com/hc/en-us/articles/1500005389362-NSFW-Server-Designation
    pub nsfw_level: NsfwLevel,
    /// All of the guild's custom stickers.
    pub stickers: ExtractMap<StickerId, Sticker>,
    /// Whether the guild has the boost progress bar enabled
    pub premium_progress_bar_enabled: bool,
}

#[cfg(feature = "model")]
impl PartialGuild {
    /// Gets all auto moderation [`Rule`]s of this guild via HTTP.
    ///
    /// **Note**: Requires the [Manage Guild] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the guild is unavailable.
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    pub async fn automod_rules(self, http: &Http) -> Result<Vec<Rule>> {
        self.id.automod_rules(http).await
    }

    /// Gets an auto moderation [`Rule`] of this guild by its ID via HTTP.
    ///
    /// **Note**: Requires the [Manage Guild] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if a rule with the given ID does not exist.
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    pub async fn automod_rule(&self, http: &Http, rule_id: RuleId) -> Result<Rule> {
        self.id.automod_rule(http, rule_id).await
    }

    /// Creates an auto moderation [`Rule`] in the guild.
    ///
    /// **Note**: Requires the [Manage Guild] permission.
    ///
    /// # Examples
    ///
    /// See [`GuildId::create_automod_rule`] for details.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission, or if invalid data is given.
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    pub async fn create_automod_rule(
        &self,
        http: &Http,
        builder: EditAutoModRule<'_>,
    ) -> Result<Rule> {
        self.id.create_automod_rule(http, builder).await
    }

    /// Edit an auto moderation [`Rule`], given its Id.
    ///
    /// **Note**: Requires the [Manage Guild] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission, or if invalid data is given.
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    pub async fn edit_automod_rule(
        &self,
        http: &Http,
        rule_id: RuleId,
        builder: EditAutoModRule<'_>,
    ) -> Result<Rule> {
        self.id.edit_automod_rule(http, rule_id, builder).await
    }

    /// Deletes an auto moderation [`Rule`] from the guild.
    ///
    /// **Note**: Requires the [Manage Guild] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission, or if a rule with that Id
    /// does not exist.
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    pub async fn delete_automod_rule(&self, http: &Http, rule_id: RuleId) -> Result<()> {
        self.id.delete_automod_rule(http, rule_id).await
    }

    /// Ban a [`User`] from the guild, deleting a number of days' worth of messages (`dmd`) between
    /// the range 0 and 7.
    ///
    /// **Note**: Requires the [Ban Members] permission.
    ///
    /// # Examples
    ///
    /// Ban a member and remove all messages they've sent in the last 4 days:
    ///
    /// ```rust,ignore
    /// // assumes a `user` and `guild` have already been bound
    /// let _ = guild.ban(user, 4);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a [`ModelError::TooLarge`] if the number of days' worth of messages
    /// to delete is over the maximum.
    ///
    /// Also may return [`Error::Http`] if the current user lacks permission.
    ///
    /// [Ban Members]: Permissions::BAN_MEMBERS
    pub async fn ban(&self, http: &Http, user: UserId, dmd: u8) -> Result<()> {
        self.ban_with_reason(http, user, dmd, "").await
    }

    /// Ban a [`User`] from the guild with a reason. Refer to [`Self::ban`] to further
    /// documentation.
    ///
    /// # Errors
    ///
    /// In addition to the reasons [`Self::ban`] may return an error, can also return an error if
    /// the reason is too long.
    pub async fn ban_with_reason(
        &self,
        http: &Http,
        user: UserId,
        dmd: u8,
        reason: &str,
    ) -> Result<()> {
        self.id.ban_with_reason(http, user, dmd, reason).await
    }

    /// Gets a list of the guild's bans, with additional options and filtering. See
    /// [`Http::get_bans`] for details.
    ///
    /// Requires the [Ban Members] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission.
    ///
    /// [Ban Members]: Permissions::BAN_MEMBERS
    pub async fn bans(
        &self,
        http: &Http,
        target: Option<UserPagination>,
        limit: Option<NonMaxU16>,
    ) -> Result<Vec<Ban>> {
        self.id.bans(http, target, limit).await
    }

    /// Gets a list of the guild's audit log entries
    ///
    /// **Note**: Requires the [View Audit Log] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission, or if an invalid value is
    /// given.
    ///
    /// [View Audit Log]: Permissions::VIEW_AUDIT_LOG
    pub async fn audit_logs(
        &self,
        http: &Http,
        action_type: Option<audit_log::Action>,
        user_id: Option<UserId>,
        before: Option<AuditLogEntryId>,
        limit: Option<NonMaxU8>,
    ) -> Result<AuditLogs> {
        self.id.audit_logs(http, action_type, user_id, before, limit).await
    }

    /// Gets all of the guild's channels over the REST API.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user is not in the guild or if the guild is
    /// otherwise unavailable.
    pub async fn channels(&self, http: &Http) -> Result<ExtractMap<ChannelId, GuildChannel>> {
        self.id.channels(http).await
    }

    /// Creates a [`GuildChannel`] in the guild.
    ///
    /// Refer to [`Http::create_channel`] for more information.
    ///
    /// **Note**: Requires the [Manage Channels] permission.
    ///
    /// # Examples
    ///
    /// Create a voice channel in a guild with the name `test`:
    ///
    /// ```rust,no_run
    /// # use serenity::http::Http;
    /// # use serenity::model::guild::PartialGuild;
    /// # use serenity::model::id::GuildId;
    /// use serenity::builder::CreateChannel;
    /// use serenity::model::channel::ChannelType;
    ///
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// # let http: Http = unimplemented!();
    /// # let guild = PartialGuild::get(&http, GuildId::new(7)).await?;
    /// let builder = CreateChannel::new("my-test-channel").kind(ChannelType::Text);
    ///
    /// // assuming a `guild` has already been bound
    /// let _channel = guild.create_channel(&http, builder).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// If the `cache` is enabled, returns a [`ModelError::InvalidPermissions`] if the current user
    /// lacks permission. Otherwise returns [`Error::Http`], as well as if invalid data is given.
    ///
    /// [Manage Channels]: Permissions::MANAGE_CHANNELS
    pub async fn create_channel(
        &self,
        cache_http: impl CacheHttp,
        builder: CreateChannel<'_>,
    ) -> Result<GuildChannel> {
        self.id.create_channel(cache_http, builder).await
    }

    /// Creates an emoji in the guild with a name and base64-encoded image.
    ///
    /// Refer to the documentation for [`Guild::create_emoji`] for more information.
    ///
    /// Requires the [Create Guild Expressions] permission.
    ///
    /// # Examples
    ///
    /// See the [`EditProfile::avatar`] example for an in-depth example as to how to read an image
    /// from the filesystem and encode it as base64. Most of the example can be applied similarly
    /// for this method.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission, if the emoji name is too
    /// long, or if the image is too large.
    ///
    /// [`EditProfile::avatar`]: crate::builder::EditProfile::avatar
    /// [`utils::read_image`]: crate::utils::read_image
    /// [Create Guild Expressions]: Permissions::CREATE_GUILD_EXPRESSIONS
    pub async fn create_emoji(&self, http: &Http, name: &str, image: &str) -> Result<Emoji> {
        self.id.create_emoji(http, name, image).await
    }

    /// Creates an integration for the guild.
    ///
    /// Requires the [Manage Guild] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission.
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    pub async fn create_integration(
        &self,
        http: &Http,
        integration_id: IntegrationId,
        kind: &str,
    ) -> Result<()> {
        self.id.create_integration(http, integration_id, kind).await
    }

    /// Create a guild specific application [`Command`].
    ///
    /// **Note**: Unlike global commands, guild commands will update instantly.
    ///
    /// # Errors
    ///
    /// See [`CreateCommand::execute`] for a list of possible errors.
    ///
    /// [`CreateCommand::execute`]: ../../builder/struct.CreateCommand.html#method.execute
    pub async fn create_command(&self, http: &Http, builder: CreateCommand<'_>) -> Result<Command> {
        self.id.create_command(http, builder).await
    }

    /// Override all guild application commands.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::create_command`].
    pub async fn set_commands(
        &self,
        http: &Http,
        commands: &[CreateCommand<'_>],
    ) -> Result<Vec<Command>> {
        self.id.set_commands(http, commands).await
    }

    /// Overwrites permissions for a specific command.
    ///
    /// **Note**: It will update instantly.
    ///
    /// # Errors
    ///
    /// See [`CreateCommandPermissionsData::execute`] for a list of possible errors.
    ///
    /// [`CreateCommandPermissionsData::execute`]: ../../builder/struct.CreateCommandPermissionsData.html#method.execute
    pub async fn edit_command_permissions(
        &self,
        http: &Http,
        command_id: CommandId,
        builder: EditCommandPermissions<'_>,
    ) -> Result<CommandPermissions> {
        self.id.edit_command_permissions(http, command_id, builder).await
    }

    /// Get all guild application commands.
    ///
    /// # Errors
    ///
    /// If there is an error, it will be either [`Error::Http`] or [`Error::Json`].
    pub async fn get_commands(&self, http: &Http) -> Result<Vec<Command>> {
        self.id.get_commands(http).await
    }

    /// Get all guild application commands with localizations.
    ///
    /// # Errors
    ///
    /// If there is an error, it will be either [`Error::Http`] or [`Error::Json`].
    pub async fn get_commands_with_localizations(&self, http: &Http) -> Result<Vec<Command>> {
        self.id.get_commands_with_localizations(http).await
    }

    /// Get a specific guild application command by its Id.
    ///
    /// # Errors
    ///
    /// If there is an error, it will be either [`Error::Http`] or [`Error::Json`].
    pub async fn get_command(&self, http: &Http, command_id: CommandId) -> Result<Command> {
        self.id.get_command(http, command_id).await
    }

    /// Edit a guild application command, given its Id.
    ///
    /// # Errors
    ///
    /// See [`CreateCommand::execute`] for a list of possible errors.
    ///
    /// [`CreateCommand::execute`]: ../../builder/struct.CreateCommand.html#method.execute
    pub async fn edit_command(
        &self,
        http: &Http,
        command_id: CommandId,
        builder: CreateCommand<'_>,
    ) -> Result<Command> {
        self.id.edit_command(http, command_id, builder).await
    }

    /// Delete guild application command by its Id.
    ///
    /// # Errors
    ///
    /// If there is an error, it will be either [`Error::Http`] or [`Error::Json`].
    pub async fn delete_command(&self, http: &Http, command_id: CommandId) -> Result<()> {
        self.id.delete_command(http, command_id).await
    }

    /// Get all guild application commands permissions only.
    ///
    /// # Errors
    ///
    /// If there is an error, it will be either [`Error::Http`] or [`Error::Json`].
    pub async fn get_commands_permissions(&self, http: &Http) -> Result<Vec<CommandPermissions>> {
        self.id.get_commands_permissions(http).await
    }

    /// Get permissions for specific guild application command by its Id.
    ///
    /// # Errors
    ///
    /// If there is an error, it will be either [`Error::Http`] or [`Error::Json`].
    pub async fn get_command_permissions(
        &self,
        http: &Http,
        command_id: CommandId,
    ) -> Result<CommandPermissions> {
        self.id.get_command_permissions(http, command_id).await
    }

    /// Creates a new role in the guild with the data set, if any.
    ///
    /// See the documentation for [`Guild::create_role`] on how to use this.
    ///
    /// **Note**: Requires the [Manage Roles] permission.
    ///
    /// # Errors
    ///
    /// If the `cache` is enabled, returns a [`ModelError::InvalidPermissions`] if the current user
    /// lacks permission. Otherwise returns [`Error::Http`], as well as if invalid data is given.
    ///
    /// [Manage Roles]: Permissions::MANAGE_ROLES
    pub async fn create_role(&self, http: &Http, builder: EditRole<'_>) -> Result<Role> {
        self.id.create_role(http, builder).await
    }

    /// Creates a new sticker in the guild with the data set, if any.
    ///
    /// **Note**: Requires the [Create Guild Expressions] permission.
    ///
    /// # Errors
    ///
    /// If the `cache` is enabled, returns a [`ModelError::InvalidPermissions`] if the current user
    /// lacks permission. Otherwise returns [`Error::Http`], as well as if invalid data is given.
    ///
    /// [Create Guild Expressions]: Permissions::CREATE_GUILD_EXPRESSIONS
    pub async fn create_sticker<'a>(
        &self,
        cache_http: impl CacheHttp,
        builder: CreateSticker<'a>,
    ) -> Result<Sticker> {
        self.id.create_sticker(cache_http, builder).await
    }

    /// Deletes the current guild if the current user is the owner of the
    /// guild.
    ///
    /// **Note**: Requires the current user to be the owner of the guild.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user is not the owner of
    /// the guild.
    pub async fn delete(&self, http: &Http) -> Result<()> {
        self.id.delete(http).await
    }

    /// Deletes an [`Emoji`] from the guild.
    ///
    /// **Note**: If the emoji was created by the current user, requires either the [Create Guild
    /// Expressions] or the [Manage Guild Expressions] permission. Otherwise, the [Manage Guild
    /// Expressions] permission is required.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission, or if an emoji with the given
    /// id does not exist in the guild.
    ///
    /// [Create Guild Expressions]: Permissions::CREATE_GUILD_EXPRESSIONS
    /// [Manage Guild Expressions]: Permissions::MANAGE_GUILD_EXPRESSIONS
    pub async fn delete_emoji(&self, http: &Http, emoji_id: EmojiId) -> Result<()> {
        self.id.delete_emoji(http, emoji_id).await
    }

    /// Deletes an integration by Id from the guild.
    ///
    /// Requires the [Manage Guild] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission, or if an integration with
    /// that Id does not exist in the guild.
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    pub async fn delete_integration(
        &self,
        http: &Http,
        integration_id: IntegrationId,
    ) -> Result<()> {
        self.id.delete_integration(http, integration_id).await
    }

    /// Deletes a [`Role`] by Id from the guild.
    ///
    /// Also see [`Role::delete`] if you have the `cache` and `model` features enabled.
    ///
    /// Requires the [Manage Roles] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission, or if a Role with that Id
    /// does not exist in the Guild.
    ///
    /// [Manage Roles]: Permissions::MANAGE_ROLES
    pub async fn delete_role(&self, http: &Http, role_id: RoleId) -> Result<()> {
        self.id.delete_role(http, role_id).await
    }

    /// Deletes a [`Sticker`] by Id from the guild.
    ///
    /// **Note**: If the sticker was created by the current user, requires either the [Create Guild
    /// Expressions] or the [Manage Guild Expressions] permission. Otherwise, the [Manage Guild
    /// Expressions] permission is required.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission, or if a sticker with that id
    /// does not exist.
    ///
    /// [Create Guild Expressions]: Permissions::CREATE_GUILD_EXPRESSIONS
    /// [Manage Guild Expressions]: Permissions::MANAGE_GUILD_EXPRESSIONS
    pub async fn delete_sticker(&self, http: &Http, sticker_id: StickerId) -> Result<()> {
        self.id.delete_sticker(http, sticker_id).await
    }

    /// Edits the current guild with new data where specified.
    ///
    /// **Note**: Requires the [Manage Guild] permission.
    ///
    /// # Errors
    ///
    /// If the `cache` is enabled, returns a [`ModelError::InvalidPermissions`] if the current user
    /// lacks permission. Otherwise returns [`Error::Http`], as well as if invalid data is given.
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    pub async fn edit(&mut self, cache_http: impl CacheHttp, builder: EditGuild<'_>) -> Result<()> {
        let guild = self.id.edit(cache_http, builder).await?;

        self.afk_metadata = guild.afk_metadata;
        self.default_message_notifications = guild.default_message_notifications;
        self.emojis = guild.emojis;
        self.features = guild.features;
        self.icon = guild.icon;
        self.mfa_level = guild.mfa_level;
        self.name = guild.name;
        self.owner_id = guild.owner_id;
        self.roles = guild.roles;
        self.splash = guild.splash;
        self.verification_level = guild.verification_level;

        Ok(())
    }

    /// Edits an [`Emoji`]'s name in the guild.
    ///
    /// **Note**: If the emoji was created by the current user, requires either the [Create Guild
    /// Expressions] or the [Manage Guild Expressions] permission. Otherwise, the [Manage Guild
    /// Expressions] permission is required.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission, or if an emoji with the given
    /// id does not exist.
    ///
    /// [Create Guild Expressions]: Permissions::CREATE_GUILD_EXPRESSIONS
    /// [Manage Guild Expressions]: Permissions::MANAGE_GUILD_EXPRESSIONS
    pub async fn edit_emoji(&self, http: &Http, emoji_id: EmojiId, name: &str) -> Result<Emoji> {
        self.id.edit_emoji(http, emoji_id, name).await
    }

    /// Edits the properties a guild member, such as muting or nicknaming them. Returns the new
    /// member.
    ///
    /// Refer to the documentation of [`EditMember`] for a full list of methods and permission
    /// restrictions.
    ///
    /// # Examples
    ///
    /// See [`GuildId::edit_member`] for details.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission, or if invalid data is given.
    pub async fn edit_member(
        &self,
        http: &Http,
        user_id: UserId,
        builder: EditMember<'_>,
    ) -> Result<Member> {
        self.id.edit_member(http, user_id, builder).await
    }

    /// Edits the guild's MFA level. Returns the new level on success.
    ///
    /// Requires guild ownership.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission.
    pub async fn edit_mfa_level(
        &self,
        http: &Http,
        mfa_level: MfaLevel,
        audit_log_reason: Option<&str>,
    ) -> Result<MfaLevel> {
        self.id.edit_mfa_level(http, mfa_level, audit_log_reason).await
    }

    /// Edits the current user's nickname for the guild.
    ///
    /// Pass [`None`] to reset the nickname.
    ///
    /// **Note**: Requires the [Change Nickname] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission to change their nickname.
    ///
    /// [Change Nickname]: Permissions::CHANGE_NICKNAME
    pub async fn edit_nickname(&self, http: &Http, new_nickname: Option<&str>) -> Result<()> {
        self.id.edit_nickname(http, new_nickname).await
    }

    /// Edits a role, optionally setting its fields.
    ///
    /// **Note**: Requires the [Manage Roles] permission.
    ///
    /// # Examples
    ///
    /// See the documentation of [`GuildId::edit_role`] for details.
    ///
    /// # Errors
    ///
    /// If the `cache` is enabled, returns a [`ModelError::InvalidPermissions`] if the current user
    /// lacks permission. Otherwise returns [`Error::Http`], as well as if invalid data is given.
    ///
    /// [Manage Roles]: Permissions::MANAGE_ROLES
    pub async fn edit_role(
        &self,
        cache_http: impl CacheHttp,
        role_id: RoleId,
        builder: EditRole<'_>,
    ) -> Result<Role> {
        self.id.edit_role(cache_http, role_id, builder).await
    }

    /// Edits the order of [`Role`]s. Requires the [Manage Roles] permission.
    ///
    /// # Examples
    ///
    /// Change the order of a role:
    ///
    /// ```rust,ignore
    /// use serenity::model::id::RoleId;
    /// partial_guild.edit_role_position(&context, RoleId::new(8), 2);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission.
    ///
    /// [Manage Roles]: Permissions::MANAGE_ROLES
    pub async fn edit_role_position(
        &self,
        http: &Http,
        role_id: RoleId,
        position: i16,
    ) -> Result<Vec<Role>> {
        self.id.edit_role_position(http, role_id, position).await
    }

    /// Edits a sticker.
    ///
    /// **Note**: If the sticker was created by the current user, requires either the [Create Guild
    /// Expressions] or the [Manage Guild Expressions] permission. Otherwise, the [Manage Guild
    /// Expressions] permission is required.
    ///
    /// # Examples
    ///
    /// Rename a sticker:
    ///
    /// ```rust,no_run
    /// # use serenity::http::Http;
    /// # use serenity::model::guild::PartialGuild;
    /// # use serenity::model::id::GuildId;
    /// use serenity::builder::EditSticker;
    /// use serenity::model::id::StickerId;
    ///
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// # let http: Http = unimplemented!();
    /// # let guild = PartialGuild::get(&http, GuildId::new(7)).await?;
    /// let builder = EditSticker::new().name("Bun bun meow");
    /// guild.edit_sticker(&http, StickerId::new(7), builder).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission, or if invalid data is given.
    ///
    /// [Create Guild Expressions]: Permissions::CREATE_GUILD_EXPRESSIONS
    /// [Manage Guild Expressions]: Permissions::MANAGE_GUILD_EXPRESSIONS
    pub async fn edit_sticker(
        &self,
        http: &Http,
        sticker_id: StickerId,
        builder: EditSticker<'_>,
    ) -> Result<Sticker> {
        self.id.edit_sticker(http, sticker_id, builder).await
    }

    /// Edits the guild's welcome screen.
    ///
    /// **Note**: Requires the [Manage Guild] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission.
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    pub async fn edit_welcome_screen(
        &self,
        http: &Http,
        builder: EditGuildWelcomeScreen<'_>,
    ) -> Result<GuildWelcomeScreen> {
        self.id.edit_welcome_screen(http, builder).await
    }

    /// Edits the guild's widget.
    ///
    /// **Note**: Requires the [Manage Guild] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission.
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    pub async fn edit_widget(
        &self,
        http: &Http,
        builder: EditGuildWidget<'_>,
    ) -> Result<GuildWidget> {
        self.id.edit_widget(http, builder).await
    }

    /// Gets a partial amount of guild data by its Id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user is not
    /// in the guild.
    pub async fn get(cache_http: impl CacheHttp, guild_id: GuildId) -> Result<PartialGuild> {
        guild_id.to_partial_guild(cache_http).await
    }

    /// Calculate a [`Member`]'s permissions in the guild.
    #[must_use]
    pub fn member_permissions(&self, member: &Member) -> Permissions {
        Guild::_user_permissions_in(
            None,
            member.user.id,
            &member.roles,
            self.id,
            &self.roles,
            self.owner_id,
        )
    }

    /// Calculate a [`PartialMember`]'s permissions in a given channel in a guild.
    ///
    /// # Panics
    ///
    /// Panics if the passed [`UserId`] does not match the [`PartialMember`] id, if user is Some.
    #[must_use]
    pub fn partial_member_permissions_in(
        &self,
        channel: &GuildChannel,
        member_id: UserId,
        member: &PartialMember,
    ) -> Permissions {
        if let Some(user) = &member.user {
            assert_eq!(user.id, member_id, "User::id does not match provided PartialMember");
        }

        Guild::_user_permissions_in(
            Some(channel),
            member_id,
            &member.roles,
            self.id,
            &self.roles,
            self.owner_id,
        )
    }

    /// Re-orders the channels of the guild.
    ///
    /// Although not required, you should specify all channels' positions, regardless of whether
    /// they were updated. Otherwise, positioning can sometimes get weird.
    ///
    /// **Note**: Requires the [Manage Channels] permission.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Http`] if the current user is lacking permission.
    ///
    /// [Manage Channels]: Permissions::MANAGE_CHANNELS
    pub async fn reorder_channels(
        &self,
        http: &Http,
        channels: impl IntoIterator<Item = (ChannelId, u64)>,
    ) -> Result<()> {
        self.id.reorder_channels(http, channels).await
    }

    /// Returns a list of [`Member`]s in a [`Guild`] whose username or nickname starts with a
    /// provided string.
    ///
    /// Optionally pass in the `limit` to limit the number of results. Minimum value is 1, maximum
    /// and default value is 1000.
    ///
    /// **Note**: Queries are case insensitive.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Http`] if the API returns an error.
    pub async fn search_members(
        &self,
        http: &Http,
        query: &str,
        limit: Option<NonMaxU16>,
    ) -> Result<Vec<Member>> {
        self.id.search_members(http, query, limit).await
    }

    /// Starts a prune of [`Member`]s.
    ///
    /// See the documentation on [`GuildPrune`] for more information.
    ///
    /// **Note**: Requires [Kick Members] and [Manage Guild] permissions.
    ///
    /// # Errors
    ///
    /// If the `cache` is enabled, returns a [`ModelError::InvalidPermissions`] if the current user
    /// does not have permission to kick members.
    ///
    /// Otherwise will return [`Error::Http`] if the current user does not have permission.
    ///
    /// Can also return an [`Error::Json`] if there is an error deserializing the API response.
    ///
    /// [Kick Members]: Permissions::KICK_MEMBERS
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    /// [`Error::Http`]: crate::error::Error::Http
    /// [`Error::Json`]: crate::error::Error::Json
    pub async fn start_prune(&self, cache_http: impl CacheHttp, days: u8) -> Result<GuildPrune> {
        self.id.start_prune(cache_http.http(), days).await
    }

    /// Kicks a [`Member`] from the guild.
    ///
    /// Requires the [Kick Members] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the member cannot be kicked by the current user.
    ///
    /// [Kick Members]: Permissions::KICK_MEMBERS
    pub async fn kick(&self, http: &Http, user_id: UserId) -> Result<()> {
        self.id.kick(http, user_id).await
    }

    /// # Errors
    ///
    /// In addition to the reasons [`Self::kick`] may return an error, can also return an error if
    /// the reason is too long.
    pub async fn kick_with_reason(&self, http: &Http, user_id: UserId, reason: &str) -> Result<()> {
        self.id.kick_with_reason(http, user_id, reason).await
    }

    /// Returns a formatted URL of the guild's icon, if the guild has an icon.
    #[must_use]
    pub fn icon_url(&self) -> Option<String> {
        icon_url(self.id, self.icon.as_ref())
    }

    /// Returns a formatted URL of the guild's banner, if the guild has a banner.
    #[must_use]
    pub fn banner_url(&self) -> Option<String> {
        self.banner.as_ref().map(|banner| cdn!("/banners/{}/{}.webp", self.id, banner))
    }

    /// Gets all [`Emoji`]s of this guild via HTTP.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the guild is unavailable.
    pub async fn emojis(&self, http: &Http) -> Result<Vec<Emoji>> {
        self.id.emojis(http).await
    }

    /// Gets an [`Emoji`] of this guild by its ID via HTTP.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if an [`Emoji`] with the given Id does not exist for the guild.
    pub async fn emoji(&self, http: &Http, emoji_id: EmojiId) -> Result<Emoji> {
        self.id.emoji(http, emoji_id).await
    }

    /// Gets all integration of the guild.
    ///
    /// Requires the [Manage Guild] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission.
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    pub async fn integrations(&self, http: &Http) -> Result<Vec<Integration>> {
        self.id.integrations(http).await
    }

    /// Gets all of the guild's invites.
    ///
    /// Requires the [Manage Guild] permission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission.
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    pub async fn invites(&self, http: &Http) -> Result<Vec<RichInvite>> {
        self.id.invites(http).await
    }

    /// Returns a guild [`Member`] object for the current user.
    ///
    /// See [`Http::get_current_user_guild_member`] for more.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Http`] if the current user is not in the guild or the access token
    /// lacks the necessary scope.
    pub async fn current_user_member(&self, http: &Http) -> Result<Member> {
        self.id.current_user_member(http).await
    }

    /// Leaves the guild.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user is unable to leave the Guild, or currently is
    /// not in the guild.
    pub async fn leave(&self, http: &Http) -> Result<()> {
        self.id.leave(http).await
    }

    /// Gets a user's [`Member`] for the guild by Id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the member is not in the Guild, or if the Guild is otherwise
    /// unavailable.
    pub async fn member(&self, cache_http: impl CacheHttp, user_id: UserId) -> Result<Member> {
        self.id.member(cache_http, user_id).await
    }

    /// Gets a list of the guild's members.
    ///
    /// Optionally pass in the `limit` to limit the number of results. Minimum value is 1, maximum
    /// and default value is 1000.
    ///
    /// Optionally pass in `after` to offset the results by a [`User`]'s Id.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Http`] if the API returns an error, may also return
    /// [`ModelError::TooSmall`] or [`ModelError::TooLarge`] if the limit is not within range.
    ///
    /// [`User`]: crate::model::user::User
    pub async fn members(
        &self,
        http: &Http,
        limit: Option<NonMaxU16>,
        after: Option<UserId>,
    ) -> Result<Vec<Member>> {
        self.id.members(http, limit, after).await
    }

    /// Moves a member to a specific voice channel.
    ///
    /// Requires the [Move Members] permission.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Http`] if the current user lacks permission, or if the member is not
    /// currently in a voice channel for this Guild.
    ///
    /// [Move Members]: Permissions::MOVE_MEMBERS
    pub async fn move_member(
        &self,
        http: &Http,
        user_id: UserId,
        channel_id: ChannelId,
    ) -> Result<Member> {
        self.id.move_member(http, user_id, channel_id).await
    }

    /// Calculate a [`Member`]'s permissions in a given channel in the guild.
    #[must_use]
    pub fn user_permissions_in(&self, channel: &GuildChannel, member: &Member) -> Permissions {
        Guild::_user_permissions_in(
            Some(channel),
            member.user.id,
            &member.roles,
            self.id,
            &self.roles,
            self.owner_id,
        )
    }

    /// Gets the number of [`Member`]s that would be pruned with the given number of days.
    ///
    /// Requires the [Kick Members] permission.
    ///
    /// See [`Guild::prune_count`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the current user lacks permission.
    ///
    /// [Kick Members]: Permissions::KICK_MEMBERS
    /// [`Guild::prune_count`]: crate::model::guild::Guild::prune_count
    pub async fn prune_count(&self, http: &Http, days: u8) -> Result<GuildPrune> {
        self.id.prune_count(http, days).await
    }

    /// Returns the Id of the shard associated with the guild.
    ///
    /// See the documentation for [`GuildId::shard_id`].
    #[must_use]
    #[cfg(feature = "utils")]
    pub fn shard_id(&self, shard_total: std::num::NonZeroU16) -> u16 {
        self.id.shard_id(shard_total)
    }

    /// Returns the formatted URL of the guild's splash image, if one exists.
    #[must_use]
    pub fn splash_url(&self) -> Option<String> {
        self.splash.as_ref().map(|splash| cdn!("/splashes/{}/{}.webp?size=4096", self.id, splash))
    }

    /// Starts an integration sync for the given integration Id.
    ///
    /// Requires the [Manage Guild] permission.
    ///
    /// # Errors
    ///
    /// See [`Guild::start_integration_sync`].
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    /// [`Guild::start_integration_sync`]: crate::model::guild::Guild::start_integration_sync
    pub async fn start_integration_sync(
        &self,
        http: &Http,
        integration_id: IntegrationId,
    ) -> Result<()> {
        self.id.start_integration_sync(http, integration_id).await
    }

    /// Unbans a [`User`] from the guild.
    ///
    /// Requires the [Ban Members] permission.
    ///
    /// # Errors
    ///
    /// See [`Guild::unban`].
    ///
    /// [Ban Members]: Permissions::BAN_MEMBERS
    /// [`Guild::unban`]: crate::model::guild::Guild::unban
    pub async fn unban(&self, http: &Http, user_id: UserId) -> Result<()> {
        self.id.unban(http, user_id).await
    }

    /// Retrieve's the guild's vanity URL.
    ///
    /// **Note**: Requires the [Manage Guild] permission.
    ///
    /// # Errors
    ///
    /// See [`Guild::vanity_url`].
    ///
    /// [Manage Guild]: Permissions::MANAGE_GUILD
    /// [`Guild::vanity_url`]: crate::model::guild::Guild::vanity_url
    pub async fn vanity_url(&self, http: &Http) -> Result<String> {
        self.id.vanity_url(http).await
    }

    /// Retrieves the guild's webhooks.
    ///
    /// **Note**: Requires the [Manage Webhooks] permission.
    ///
    /// # Errors
    ///
    /// See [`Guild::webhooks`].
    ///
    /// [Manage Webhooks]: Permissions::MANAGE_WEBHOOKS
    /// [`Guild::webhooks`]: crate::model::guild::Guild::webhooks
    pub async fn webhooks(&self, http: &Http) -> Result<Vec<Webhook>> {
        self.id.webhooks(http).await
    }

    /// Obtain a reference to a role by its name.
    ///
    /// **Note**: If two or more roles have the same name, obtained reference will be one of them.
    ///
    /// # Examples
    ///
    /// Obtain a reference to a [`Role`] by its name.
    ///
    /// ```rust,no_run
    /// # use serenity::model::prelude::*;
    /// # use serenity::prelude::*;
    /// # struct Handler;
    ///
    /// #[serenity::async_trait]
    /// #[cfg(all(feature = "cache", feature = "client"))]
    /// impl EventHandler for Handler {
    ///     async fn message(&self, ctx: &Context, msg: &Message) {
    ///         if let Some(guild_id) = msg.guild_id {
    ///             if let Some(guild) = guild_id.to_guild_cached(&ctx.cache) {
    ///                 if let Some(role) = guild.role_by_name("role_name") {
    ///                     println!("Obtained role's reference: {:?}", role);
    ///                 }
    ///             }
    ///         }
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn role_by_name(&self, role_name: &str) -> Option<&Role> {
        self.roles.iter().find(|role| role_name == &*role.name)
    }

    /// Returns a builder which can be awaited to obtain a message or stream of messages in this
    /// guild.
    #[cfg(feature = "collector")]
    pub fn await_reply(&self, shard_messenger: ShardMessenger) -> MessageCollector {
        MessageCollector::new(shard_messenger).guild_id(self.id)
    }

    /// Same as [`Self::await_reply`].
    #[cfg(feature = "collector")]
    pub fn await_replies(&self, shard_messenger: ShardMessenger) -> MessageCollector {
        self.await_reply(shard_messenger)
    }

    /// Returns a builder which can be awaited to obtain a message or stream of reactions sent in
    /// this guild.
    #[cfg(feature = "collector")]
    pub fn await_reaction(&self, shard_messenger: ShardMessenger) -> ReactionCollector {
        ReactionCollector::new(shard_messenger).guild_id(self.id)
    }

    /// Same as [`Self::await_reaction`].
    #[cfg(feature = "collector")]
    pub fn await_reactions(&self, shard_messenger: ShardMessenger) -> ReactionCollector {
        self.await_reaction(shard_messenger)
    }

    /// Gets the guild active threads.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if there is an error in the deserialization, or if the bot issuing
    /// the request is not in the guild.
    pub async fn get_active_threads(&self, http: &Http) -> Result<ThreadsData> {
        self.id.get_active_threads(http).await
    }
}

// Manual impl needed to insert guild_id into Role's
impl<'de> Deserialize<'de> for PartialGuildGeneratedOriginal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> StdResult<Self, D::Error> {
        let mut guild = Self::deserialize(deserializer)?; // calls #[serde(remote)]-generated inherent method
        lending_for_each!(guild.roles.iter_mut(), |r| r.guild_id = guild.id);
        Ok(guild)
    }
}

impl Serialize for PartialGuildGeneratedOriginal {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> StdResult<S::Ok, S::Error> {
        Self::serialize(self, serializer) // calls #[serde(remote)]-generated inherent method
    }
}

impl From<Guild> for PartialGuild {
    /// Converts this [`Guild`] instance into a [`PartialGuild`]
    fn from(guild: Guild) -> Self {
        let (premium_progress_bar_enabled, widget_enabled) =
            (guild.premium_progress_bar_enabled(), guild.widget_enabled());

        let mut partial = Self {
            __generated_flags: PartialGuildGeneratedFlags::empty(),
            application_id: guild.application_id,
            id: guild.id,
            afk_metadata: guild.afk_metadata,
            default_message_notifications: guild.default_message_notifications,
            widget_channel_id: guild.widget_channel_id,
            emojis: guild.emojis,
            features: guild.features,
            icon: guild.icon,
            mfa_level: guild.mfa_level,
            name: guild.name,
            owner_id: guild.owner_id,
            roles: guild.roles,
            splash: guild.splash,
            discovery_splash: guild.discovery_splash,
            system_channel_id: guild.system_channel_id,
            system_channel_flags: guild.system_channel_flags,
            rules_channel_id: guild.rules_channel_id,
            public_updates_channel_id: guild.public_updates_channel_id,
            verification_level: guild.verification_level,
            description: guild.description,
            premium_tier: guild.premium_tier,
            premium_subscription_count: guild.premium_subscription_count,
            banner: guild.banner,
            vanity_url_code: guild.vanity_url_code,
            welcome_screen: guild.welcome_screen,
            approximate_member_count: guild.approximate_member_count,
            approximate_presence_count: guild.approximate_presence_count,
            nsfw_level: guild.nsfw_level,
            max_video_channel_users: guild.max_video_channel_users,
            max_presences: guild.max_presences,
            max_members: guild.max_members,
            stickers: guild.stickers,
            icon_hash: guild.icon_hash,
            explicit_content_filter: guild.explicit_content_filter,
            preferred_locale: guild.preferred_locale,
            max_stage_video_channel_users: guild.max_stage_video_channel_users,
        };
        partial.set_premium_progress_bar_enabled(premium_progress_bar_enabled);
        partial.set_widget_enabled(widget_enabled);
        partial
    }
}
