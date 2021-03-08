initSidebarItems({"enum":[["ContentModifier","Formatting modifiers for MessageBuilder content pushes"]],"fn":[["content_safe","Transforms role, channel, user, `@everyone` and `@here` mentions into raw text by using the `Cache` only."],["hashmap_to_json_map","Converts a HashMap into a final `serde_json::Map` representation."],["parse_channel","Retrieves an Id from a channel mention."],["parse_emoji","Retrieves the animated state, name and Id from an emoji mention, in the form of an `EmojiIdentifier`."],["parse_invite","Retrieves the “code” part of an invite out of a URL."],["parse_mention","Retrieve the ID number out of a channel, role, or user mention."],["parse_quotes","Turns a string into a vector of string arguments, splitting by spaces, but parsing content within quotes as one individual argument."],["parse_role","Retrieves an Id from a role mention."],["parse_username","Retrieves an Id from a user mention."],["read_image","Reads an image from a path and encodes it into base64."],["shard_id","Calculates the Id of the shard responsible for a guild, given its Id and total number of shards used."]],"struct":[["Colour","A utility struct to help with working with the basic representation of a colour. This is particularly useful when working with a `Role`’s colour, as the API works with an integer value instead of an RGB value."],["Content","Describes formatting on string content"],["ContentSafeOptions","Struct that allows to alter [`content_safe`]’s behaviour."],["CustomMessage","A builder for constructing a personal [`Message`] instance. This can be useful for emitting a manual `dispatch` to the framework, but you don’t have a message in hand, or just have a fragment of its data."],["MessageBuilder","The Message Builder is an ergonomic utility to easily build a message, by adding text and mentioning mentionable structs."]],"trait":[["EmbedMessageBuilding","A trait with additional functionality over the [`MessageBuilder`] for creating content with additional functionality available only in embeds."]],"type":[["Color",""]]});