def classify_application(hostname, application="Unknown"):

    hostname = (hostname or "").lower()
    application = (application or "").lower()

    # PROCESS DETECTION
    if "discord" in application:
        return "Discord"

    elif "steam" in application:
        return "Steam"

    elif "spotify" in application:
        return "Spotify"

    elif "chrome" in application:
        return "Chrome"

    elif "brave" in application:
        return "Brave"

    elif "firefox" in application:
        return "Firefox"

    elif "msedge" in application:
        return "Edge"

    elif "valorant" in application:
        return "Valorant"

    elif "code" in application:
        return "VS Code"

    # HOSTNAME DETECTION
    elif (
        "youtube" in hostname
        or "googlevideo" in hostname
        or "ytimg" in hostname
    ):
        return "YouTube"

    elif "github" in hostname:
        return "GitHub"

    elif "openai" in hostname:
        return "OpenAI"

    elif "leetcode" in hostname:
        return "LeetCode"

    elif "google" in hostname:
        return "Google"

    return "Unknown"