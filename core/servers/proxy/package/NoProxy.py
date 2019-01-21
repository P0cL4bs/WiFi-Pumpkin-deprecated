from collections import OrderedDict
from datetime import datetime
from functools import partial
from os import path

import core.utility.constants as C
from core.main import  QtGui,QtCore
from core.servers.proxy.package.ProxyMode import ProxyMode
from core.utility.collection import SettingsINI
from core.utility.threads import ThreadPopen
from core.utils import Refactor
from core.widgets.customiseds import AutoGridLayout
from core.widgets.docks.dockmonitor import (
    dockAreaAPI,dockUrlMonitor,dockCredsMonitor,dockPumpkinProxy,dockTCPproxy
)
from core.widgets.pluginssettings import PumpkinProxySettings
from plugins.analyzers import *
from plugins.external.scripts import *


class NoProxy(ProxyMode):
    Name="No Proxy"
    Author = "Pumpkin-Dev"
    Hidden = True

    def __init__(self, parent, **kwargs):
        super(NoProxy, self).__init__(parent)
        self.controlui.setChecked(self.FSettings.Settings.get_setting('plugins', self.Name, format=bool))
        self.controlui.toggled.connect(self.CheckOptions)
        self.setEnabled(self.FSettings.Settings.get_setting('plugins', self.Name, format=bool))
        #parent.PopUpPlugins.GroupPluginsProxy.setChecked(not self.FSettings.Settings.get_setting('plugins', self.Name, format=bool))
