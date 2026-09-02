export const SERVICE_CATALOG = [
  {
    id: 'discord',
    displayName: 'Discord',
    category: 'social',
    windows: {
      processes: ['Discord.exe', 'DiscordCanary.exe', 'DiscordPTB.exe'],
      domains: ['discord.com', 'www.discord.com', 'discord.gg', 'gateway.discord.gg', 'discordapp.com', 'discordapp.net', 'discord.media'],
    },
    android: { packages: ['com.discord'], domains: ['discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net'] },
    ios: { localSelectionKey: 'discord' },
  },
  {
    id: 'snapchat',
    displayName: 'Snapchat',
    category: 'social',
    windows: {
      processes: [],
      domains: ['snapchat.com', 'www.snapchat.com', 'web.snapchat.com', 'accounts.snapchat.com', 'profile.snapchat.com'],
    },
    android: { packages: ['com.snapchat.android'], domains: ['snapchat.com', 'web.snapchat.com'] },
    ios: { localSelectionKey: 'snapchat' },
  },
  {
    id: 'facebook',
    displayName: 'Facebook / Messenger',
    category: 'social',
    warning: 'This blocks both Facebook and Messenger because their web services share infrastructure.',
    windows: {
      processes: ['Messenger.exe'],
      domains: ['facebook.com', 'www.facebook.com', 'm.facebook.com', 'web.facebook.com', 'messenger.com', 'www.messenger.com'],
    },
    android: { packages: ['com.facebook.katana', 'com.facebook.orca'], domains: ['facebook.com', 'messenger.com'] },
    ios: { localSelectionKey: 'facebook' },
  },
  {
    id: 'instagram',
    displayName: 'Instagram',
    category: 'social',
    windows: {
      processes: ['Instagram.exe'],
      domains: ['instagram.com', 'www.instagram.com', 'api.instagram.com', 'accountscenter.instagram.com'],
    },
    android: { packages: ['com.instagram.android'], domains: ['instagram.com'] },
    ios: { localSelectionKey: 'instagram' },
  },
  {
    id: 'whatsapp',
    displayName: 'WhatsApp',
    category: 'social',
    windows: {
      processes: ['WhatsApp.exe'],
      domains: ['whatsapp.com', 'www.whatsapp.com', 'web.whatsapp.com', 'static.whatsapp.net'],
    },
    android: { packages: ['com.whatsapp', 'com.whatsapp.w4b'], domains: ['whatsapp.com', 'web.whatsapp.com'] },
    ios: { localSelectionKey: 'whatsapp' },
  },
  {
    id: 'telegram',
    displayName: 'Telegram',
    category: 'social',
    windows: {
      processes: ['Telegram.exe'],
      domains: ['telegram.org', 'www.telegram.org', 'web.telegram.org', 'webk.telegram.org', 'webz.telegram.org', 't.me', 'telegram.me'],
    },
    android: { packages: ['org.telegram.messenger'], domains: ['telegram.org', 't.me'] },
    ios: { localSelectionKey: 'telegram' },
  },
  {
    id: 'signal',
    displayName: 'Signal',
    category: 'social',
    windows: {
      processes: ['Signal.exe'],
      domains: ['signal.org', 'www.signal.org', 'chat.signal.org', 'updates.signal.org'],
    },
    android: { packages: ['org.thoughtcrime.securesms'], domains: ['signal.org'] },
    ios: { localSelectionKey: 'signal' },
  },
  {
    id: 'slack',
    displayName: 'Slack',
    category: 'social',
    windows: {
      processes: ['slack.exe'],
      domains: ['slack.com', 'www.slack.com', 'app.slack.com'],
    },
    android: { packages: ['com.Slack'], domains: ['slack.com', 'app.slack.com'] },
    ios: { localSelectionKey: 'slack' },
  },
  {
    id: 'teams',
    displayName: 'Microsoft Teams',
    category: 'social',
    warning: 'Blocking Teams may also affect school or work meetings.',
    windows: {
      processes: ['ms-teams.exe', 'Teams.exe'],
      domains: ['teams.microsoft.com', 'teams.live.com'],
    },
    android: { packages: ['com.microsoft.teams'], domains: ['teams.microsoft.com', 'teams.live.com'] },
    ios: { localSelectionKey: 'teams' },
  },
  {
    id: 'google-chat',
    displayName: 'Google Chat',
    category: 'social',
    windows: {
      processes: [],
      domains: ['chat.google.com'],
    },
    android: { packages: ['com.google.android.apps.dynamite'], domains: ['chat.google.com'] },
    ios: { localSelectionKey: 'google-chat' },
  },
  {
    id: 'google-messages',
    displayName: 'Google Messages',
    category: 'social',
    windows: {
      processes: [],
      domains: ['messages.google.com'],
    },
    android: { packages: ['com.google.android.apps.messaging'], domains: ['messages.google.com'] },
    ios: { localSelectionKey: 'google-messages' },
  },
  {
    id: 'zoom',
    displayName: 'Zoom',
    category: 'social',
    warning: 'Blocking Zoom may also affect school or work meetings.',
    windows: {
      processes: ['Zoom.exe'],
      domains: ['zoom.us', 'www.zoom.us', 'app.zoom.us'],
    },
    android: { packages: ['us.zoom.videomeetings'], domains: ['zoom.us'] },
    ios: { localSelectionKey: 'zoom' },
  },
  {
    id: 'reddit',
    displayName: 'Reddit',
    category: 'social',
    windows: {
      processes: [],
      domains: ['reddit.com', 'www.reddit.com', 'old.reddit.com', 'new.reddit.com'],
    },
    android: { packages: ['com.reddit.frontpage'], domains: ['reddit.com'] },
    ios: { localSelectionKey: 'reddit' },
  },
  {
    id: 'tiktok',
    displayName: 'TikTok',
    category: 'social',
    windows: {
      processes: ['TikTok.exe'],
      domains: ['tiktok.com', 'www.tiktok.com', 'm.tiktok.com'],
    },
    android: { packages: ['com.zhiliaoapp.musically'], domains: ['tiktok.com'] },
    ios: { localSelectionKey: 'tiktok' },
  },
  {
    id: 'x-twitter',
    displayName: 'X / Twitter',
    category: 'social',
    windows: {
      processes: [],
      domains: ['x.com', 'www.x.com', 'twitter.com', 'www.twitter.com', 'mobile.twitter.com'],
    },
    android: { packages: ['com.twitter.android'], domains: ['x.com', 'twitter.com'] },
    ios: { localSelectionKey: 'x-twitter' },
  },
  {
    id: 'roblox',
    displayName: 'Roblox',
    category: 'gaming',
    windows: {
      processes: ['RobloxPlayerBeta.exe', 'Windows10Universal.exe'],
      domains: ['roblox.com', 'www.roblox.com', 'web.roblox.com', 'api.roblox.com', 'rbxcdn.com'],
    },
    android: { packages: ['com.roblox.client'], domains: ['roblox.com', 'rbxcdn.com'] },
    ios: { localSelectionKey: 'roblox' },
  },
  {
    id: 'netflix',
    displayName: 'Netflix',
    category: 'streaming',
    windows: {
      processes: [],
      domains: ['netflix.com', 'www.netflix.com', 'nflxvideo.net', 'nflximg.net', 'nflxso.net', 'nflxext.com'],
    },
    android: { packages: ['com.netflix.mediaclient'], domains: ['netflix.com', 'nflxvideo.net'] },
    ios: { localSelectionKey: 'netflix' },
  },
  {
    id: 'paramount',
    displayName: 'Paramount+',
    category: 'streaming',
    windows: {
      processes: [],
      domains: ['paramountplus.com', 'www.paramountplus.com', 'cbsi.com', 'cbsivideo.com'],
    },
    android: { packages: ['com.cbs.app'], domains: ['paramountplus.com', 'cbsi.com', 'cbsivideo.com'] },
    ios: { localSelectionKey: 'paramount' },
  },
  {
    id: 'discovery',
    displayName: 'discovery+',
    category: 'streaming',
    windows: {
      processes: [],
      domains: ['discoveryplus.com', 'www.discoveryplus.com', 'discoveryplus.co.uk', 'dplay.com'],
    },
    android: { packages: ['com.discovery.discoveryplus.mobile'], domains: ['discoveryplus.com', 'dplay.com'] },
    ios: { localSelectionKey: 'discovery' },
  },
  {
    id: 'hulu',
    displayName: 'Hulu',
    category: 'streaming',
    windows: {
      processes: [],
      domains: ['hulu.com', 'www.hulu.com', 'huluim.com', 'hulustream.com'],
    },
    android: { packages: ['com.hulu.plus'], domains: ['hulu.com', 'huluim.com', 'hulustream.com'] },
    ios: { localSelectionKey: 'hulu' },
  },
  {
    id: 'youtube',
    displayName: 'YouTube',
    category: 'streaming',
    warning: 'Blocking YouTube may also block embedded videos and YouTube Music.',
    windows: {
      processes: [],
      domains: ['youtube.com', 'www.youtube.com', 'm.youtube.com', 'youtu.be', 'youtube-nocookie.com', 'youtubei.googleapis.com', 'googlevideo.com', 'ytimg.com'],
    },
    android: { packages: ['com.google.android.youtube'], domains: ['youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com'] },
    ios: { localSelectionKey: 'youtube' },
  },
];

export function catalogById() {
  return new Map(SERVICE_CATALOG.map((service) => [service.id, service]));
}
