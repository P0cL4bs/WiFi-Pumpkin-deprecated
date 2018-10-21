function FindProxyForURL(url, host) {
      // URLs within this network are accessed directly
      if (isInNet(host, "127.0.0.1", "255.255.255.0"))
      {
         return "DIRECT";
      }
      //return "PROXY 10.0.0.1:8080; DIRECT";
      return "DIRECT";
   }
