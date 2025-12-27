To run them from my volatility directory:


python3.13 vol.py -f C:\2025TC.dmp windows.steam_artifacts.SteamArtifacts


python3.13 vol.py -f C:\2025TC.dmp vol -f windows.meta_horizon_worlds.MetaHorizonWorlds

python3.13 vol.py -f C:\2025TC.dmp windows.ea_app_artifacts

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
    
The EA artifacts one extracts:
Process, Account and Game keys and other data using YaraScan in the plugin.

These competing approaches enable me to explore using Regex, text filters, YaraScan patterns JSON data!

TODO: Explore extracting steam credentials!
