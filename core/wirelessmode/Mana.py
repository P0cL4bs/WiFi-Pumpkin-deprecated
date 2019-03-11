from core.config.globalimport import *
import weakref
from core.utility.threads import ProcessHostapd, ThRunDhcp, ProcessThread
from core.widgets.default.uimodel import *
from core.wirelessmode.WirelessMode import Mode


class Mana(Mode):
    ConfigRoot = "Mana"
    SubConfig = "Mana"
    Name = "Mana AP Mode"
    ID = "Mana"

    def __init__(self, parent=0):
        super(Mana, self).__init__(parent)

    def Initialize(self):

        self.parent.updateSettingsAP()
        self.configure_network_AP()
        self.get_soft_dependencies()
        ignore = ('interface=', 'ssid=', 'channel=', 'essid=')
        with open(C.HOSTAPDCONF_PATH, 'w') as apconf:
            for i in self.parent.SettingsAP['hostapd']:
                apconf.write(i)
            for config in str(self.FSettings.ListHostapd.toPlainText()).split('\n'):
                if not config.startswith('#') and len(config) > 0:
                    if not config.startswith(ignore):
                        apconf.write(config + '\n')
            if self.Settings.EnableMana.isChecked():
                apconf.write('enable_mana=1'+'\n')
                if self.Settings.ManaLoud.isChecked():
                    apconf.write('mana_loud=1' + '\n')
                else:
                    apconf.write('mana_loud=0' + '\n')
                if self.Settings.ManaACL.isChecked():
                    apconf.write('mana_macl=1' + '\n')
                else:
                    apconf.write('mana_macacl=0' + '\n')
            apconf.close()

    def boot(self):
        # create thread for hostapd and connect get_Hostapd_Response function
        self.reactor = ProcessHostapd(
            {self.hostapd_path: [C.HOSTAPDCONF_PATH]}, self.parent.currentSessionID)
        self.reactor.setObjectName('ManaHostapd')
        self.reactor.statusAP_connected.connect(self.LogOutput)
        self.reactor.statusAPError.connect(self.Shutdown)

    @property
    def Settings(self):
        return ManaSettings.getInstance()


class ManaSettings(CoreSettings):
    ConfigRoot = "Mana"
    Name = "Mana"
    ID = "Mana"
    Category = "Wireless"
    instances = []

    def __init__(self, parent):
        super(ManaSettings, self).__init__(parent)
        self.__class__.instances.append(weakref.proxy(self))
        self.FSettings = SuperSettings.getInstance()
        self.setCheckable(False)
        self.hide()

        self.HostapdKarmaPath = QtGui.QLineEdit()
        self.HostapdKarmaPath.setText(self.FSettings.Settings.get_setting(
            self.ConfigRoot, '{}_hostapd_path'.format(self.ConfigRoot)))
        self.HostapdConf = QtGui.QComboBox()
        os.path.walk('core/config/hostapd', self.osWalkCallback, None)

        self.EnableMana = QtGui.QGroupBox("Enable Mana")
        self.EnableMana.setCheckable(True)
        self.EnableMana.setObjectName("enable_mana")
        self.EnableMana.setChecked(self.FSettings.Settings.get_setting(
            self.ConfigRoot, 'enable_mana', format=bool))
        self.ManaLoud = QtGui.QCheckBox("Mana Loud")
        self.ManaLoud.setObjectName("mana_loud")
        self.ManaLoud.setChecked(self.FSettings.Settings.get_setting(
            self.ConfigRoot, 'mana_loud', format=bool))
        self.ManaACL = QtGui.QCheckBox("Mana ACL")
        self.ManaACL.setObjectName("mana_macl")
        self.ManaACL.setChecked(self.FSettings.Settings.get_setting(
            self.ConfigRoot, 'mana_macacl', format=bool))
        self.KLayout = QtGui.QFormLayout()
        self.KLayout.addRow(self.ManaLoud)
        self.KLayout.addRow(self.ManaACL)
        self.EnableMana.setLayout(self.KLayout)

        self.APLayout = QtGui.QFormLayout()
        self.APLayout.addRow(QtGui.QLabel(
            "Hostapd with Mana"), self.HostapdKarmaPath)
        self.APLayout.addRow(QtGui.QLabel("Mana Conf"), self.HostapdConf)
        self.APLayout.addRow(self.EnableMana)
        self.layout.addLayout(self.APLayout)

    def osWalkCallback(self, arg, directory, files):
        for file in files:
            self.HostapdConf.addItem(os.path.join(directory, file))

    def setAP_essid_random(self):
        ''' set random mac 3 last digits  '''
        prefix = []
        for item in [x for x in str(self.EditBSSID.text()).split(':')]:
            prefix.append(int(item, 16))
        self.EditBSSID.setText(Refactor.randomMacAddress(
            [prefix[0], prefix[1], prefix[2]]).upper())

    @classmethod
    def getInstance(cls):
        return cls.instances[0]
