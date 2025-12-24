To run them from my volatility directory:


python3.13 vol.py -f C:\2025TC.dmp windows.steam_artifacts.SteamArtifacts


python3.13 vol.py -f C:\2025TC.dmp vol -f windows.meta_horizon_worlds.MetaHorizonWorlds

The steam version extracts strings, but at present no VAC or login credentials:
            "steamapps",
            "SteamID",
            "friends",
            "chat",
            "userdata",
            "Valve",
            "Lobby",
            "GameID",
            "CMServer",
            "https?://.*steampowered\.com",
            "steamwebhelper",
            "cloud"  ,

The meta world one extracts tokens and chats:
    TOKEN_REGEX "Bearer\\s+[A-Za-z0-9\\-\\._~\\+/=]+")
    CHAT_REGEX "(chat|say|message)[^\\x00]{5,200}", re.I)

These competing approaches enable me to explore using Regex and filter patterns!

TODO: Explore extracting steam credentials!
