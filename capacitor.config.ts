import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.forwardx.app',
  appName: 'ForwardX',
  webDir: 'client/dist',
  server: {
    androidScheme: 'http',
    cleartext: true,
  },
  android: {
    backgroundColor: '#f7f9fc',
  },
  plugins: {
    LocalNotifications: {
      smallIcon: 'ic_stat_forwardx',
      iconColor: '#2563eb',
    },
  },
};

export default config;
