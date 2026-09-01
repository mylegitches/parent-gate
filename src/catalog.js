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

export const PROFILE_DEFINITIONS = {
  normal: { displayName: 'Normal', blockedServices: [] },
  homework: { displayName: 'Homework', blockedServices: ['discord'] },
  'deep-focus': { displayName: 'Deep Focus', blockedCategories: ['social', 'streaming'] },
};

export function catalogById() {
  return new Map(SERVICE_CATALOG.map((service) => [service.id, service]));
}

