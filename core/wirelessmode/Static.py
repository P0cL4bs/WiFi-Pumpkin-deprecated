from core.config.globalimport import *
import weakref
from os import (
    system, path, getcwd,
    popen, listdir, mkdir, chown
)
from pwd import getpwnam
from grp import getgrnam
from time import asctime
from core.utility.threads import ProcessHostapd, ThRunDhcp, ProcessThread
from core.wirelessmode.WirelessMode import Mode
from core.widgets.default.uimodel import *


class Static(Mode):
    ConfigRoot = "Static"
    SubConfig = "Static"
    ID = "Static"
    Name = "Static AP Mode"

    def __init__(self, parent=0):
        super(Static, self).__init__(parent)
        self.confgSecurity = []

    @property
    def Settings(self):
        return StaticSettings.getInstance()

    def Initialize(self):
        self.check_Wireless_Security()
        dh, gateway = self.parent.SessionConfig.DHCP.conf['router'], str(
            self.parent.SessionConfig.DHCP.EditGateway.text())
        if dh[:len(dh) - len(dh.split('.').pop())] == gateway[:len(gateway) - len(gateway.split('.').pop())]:
            return QtGui.QMessageBox.warning(self, 'DHCP Server settings',
                                             'The DHCP server check if range ip class is same.'
                                             'it works, but not share internet connection in some case.\n'
                                             'for fix this, You need change on tab (settings -> Class Ranges)'
                                             'now you have choose the Class range different of your network.')

        # Check the key
        if self.Settings.WSLayout.isChecked():
            if 1 <= self.Settings.WPAtype_spinbox.value() <= 2:
                if not (8 <= len(self.Settings.editPasswordAP.text()) <= 63 and is_ascii(
                        str(self.Settings.editPasswordAP.text()))):
                    return self.check_key_security_invalid()
            if self.Settings.WPAtype_spinbox.value() == 0:
                if not (len(self.Settings.editPasswordAP.text()) == 5 or len(
                        self.Settings.editPasswordAP.text()) == 13) and is_ascii(
                        str(self.Settings.editPasswordAP.text())) \
                        and not ((len(self.Settings.editPasswordAP.text()) == 10 or len(
                            self.Settings.editPasswordAP.text()) == 24) and is_hexadecimal(
                            str(self.Settings.editPasswordAP.text()))):
                    return self.check_key_security_invalid()
        # get Tab-Hostapd conf and configure hostapd
        self.parent.updateSettingsAP()  # update settings to resettings options ap
        self.configure_network_AP()
        self.check_Wireless_Security()  # check if user set wireless password
        ignore = ('interface=', 'ssid=', 'channel=', 'essid=')
        with open(C.HOSTAPDCONF_PATH, 'w') as apconf:
            for i in self.parent.SettingsAP['hostapd']:
                apconf.write(i)
            for config in str(self.FSettings.ListHostapd.toPlainText()).split('\n'):
                if not config.startswith('#') and len(config) > 0:
                    if not config.startswith(ignore):
                        apconf.write(config + '\n')
            apconf.close()

    def boot(self):
        # create thread for hostapd and connect get_Hostapd_Response function
        self.reactor = ProcessHostapd(
            {self.hostapd_path: [C.HOSTAPDCONF_PATH]}, self.parent.currentSessionID)
        self.reactor.setObjectName('StaticHostapd')
        self.reactor.statusAP_connected.connect(self.LogOutput)
        self.reactor.statusAPError.connect(self.Shutdown)

    def LogOutput(self, data):
        if self.parent.Home.DHCP.ClientTable.APclients != {}:
            if data in self.parent.Home.DHCP.ClientTable.APclients.keys():
                self.parent.StationMonitor.addRequests(
                    data, self.parent.Home.DHCP.ClientTable.APclients[data], False)
            self.parent.Home.DHCP.ClientTable.delete_item(data)
            self.parent.connectedCount.setText(
                str(len(self.parent.Home.DHCP.ClientTable.APclients.keys())))

    def check_key_security_invalid(self):
        return QtGui.QMessageBox.warning(self, 'Security Key',
                                         'This Key can not be used.\n'
                                         'The requirements for a valid key are:\n\n'
                                         'WPA:\n'
                                         '- 8 to 63 ASCII characters\n\n'
                                         'WEP:\n'
                                         '- 5/13 ASCII characters or 13/26 hexadecimal characters')

    def check_Wireless_Security(self):
        '''check if user add security password on AP'''
        # New Implementation after refactored
        if self.Settings.WSLayout.isChecked():
            self.confgSecurity = []
            if 1 <= self.Settings.WPAtype_spinbox.value() <= 2:
                self.confgSecurity.append('wpa={}\n'.format(
                    str(self.Settings.WPAtype_spinbox.value())))
                self.confgSecurity.append('wpa_key_mgmt=WPA-PSK\n')
                self.confgSecurity.append('wpa_passphrase={}\n'.format(
                    self.Settings.editPasswordAP.text()))
                if '+' in self.Settings.wpa_pairwiseCB.currentText():
                    self.confgSecurity.append('wpa_pairwise=TKIP CCMP\n')
                else:
                    self.confgSecurity.append('wpa_pairwise={}\n'.format(
                        self.Settings.wpa_pairwiseCB.currentText()))

            if self.Settings.WPAtype_spinbox.value() == 0:
                self.confgSecurity.append('auth_algs=1\n')
                self.confgSecurity.append('wep_default_key=0\n')
                if len(self.Settings.editPasswordAP.text()) == 5 or len(self.Settings.editPasswordAP.text()) == 13:
                    self.confgSecurity.append('wep_key0="{}"\n'.format(
                        self.Settings.editPasswordAP.text()))
                else:
                    self.confgSecurity.append('wep_key0={}\n'.format(
                        self.Settings.editPasswordAP.text()))

            for config in self.confgSecurity:
                self.parent.SettingsAP['hostapd'].append(config)
            self.FSettings.Settings.set_setting(
                'accesspoint', 'WPA_SharedKey', self.Settings.editPasswordAP.text())
            self.FSettings.Settings.set_setting(
                'accesspoint', 'WPA_Algorithms', self.Settings.wpa_pairwiseCB.currentText())
            self.FSettings.Settings.set_setting(
                'accesspoint', 'WPA_type', self.Settings.WPAtype_spinbox.value())


class StaticSettings(CoreSettings):
    Name = "Static"
    ID = "Static"
    Category = "Wireless"
    instances = []

    def __init__(self, parent):
        super(StaticSettings, self).__init__(parent)
        self.__class__.instances.append(weakref.proxy(self))
        self.FSettings = SuperSettings.getInstance()
        self.setCheckable(False)
        self.hide()

        self.WSLayout = QtGui.QGroupBox()
        self.WSLayout.setTitle("Wireless Security")
        self.WSLayout.setFixedWidth(300)
        self.WSLayout.setCheckable(True)
        self.WSLayout.setChecked(
            self.FSettings.Settings.get_setting('accesspoint', 'enable_Security', format=bool))
        self.WSLayout.clicked.connect(self.check_StatusWPA_Security)

        self.WSGrid = QtGui.QGridLayout()
        self.editPasswordAP = QtGui.QLineEdit(
            self.FSettings.Settings.get_setting('accesspoint', 'WPA_SharedKey'))
        self.WPAtype_spinbox = QtGui.QSpinBox()
        self.wpa_pairwiseCB = QtGui.QComboBox()
        self.lb_type_security = QtGui.QLabel()
        wpa_algotims = self.FSettings.Settings.get_setting(
            'accesspoint', 'WPA_Algorithms')
        self.wpa_pairwiseCB.addItems(C.ALGORITMS)
        self.wpa_pairwiseCB.setCurrentIndex(C.ALGORITMS.index(wpa_algotims))
        self.WPAtype_spinbox.setMaximum(2)
        self.WPAtype_spinbox.setMinimum(0)
        self.WPAtype_spinbox.setValue(self.FSettings.Settings.get_setting(
            'accesspoint', 'WPA_type', format=int))
        self.editPasswordAP.setFixedWidth(150)
        self.editPasswordAP.textChanged.connect(self.update_security_settings)
        self.WPAtype_spinbox.valueChanged.connect(
            self.update_security_settings)
        self.update_security_settings()

        # add widgets on layout Group
        self.WSGrid.addWidget(QtGui.QLabel('Security type:'), 0, 0)
        self.WSGrid.addWidget(self.WPAtype_spinbox, 0, 1)
        self.WSGrid.addWidget(self.lb_type_security, 0, 2)
        self.WSGrid.addWidget(QtGui.QLabel('WPA Algorithms:'), 1, 0)
        self.WSGrid.addWidget(self.wpa_pairwiseCB, 1, 1)
        self.WSGrid.addWidget(QtGui.QLabel('Security Key:'), 2, 0)
        self.WSGrid.addWidget(self.editPasswordAP, 2, 1)

        self.WSLayout.setLayout(self.WSGrid)
        self.APLayout = QtGui.QFormLayout()
        self.APLayout.addRow(self.WSLayout)
        self.layout.addLayout(self.APLayout)

    def check_StatusWPA_Security(self):
        '''simple connect for get status security wireless click'''
        self.FSettings.Settings.set_setting('accesspoint',
                                            'enable_security', self.WSLayout.isChecked())

    def setAP_essid_random(self):
        ''' set random mac 3 last digits  '''
        prefix = []
        for item in [x for x in str(self.EditBSSID.text()).split(':')]:
            prefix.append(int(item, 16))
        self.EditBSSID.setText(Refactor.randomMacAddress(
            [prefix[0], prefix[1], prefix[2]]).upper())

    def update_security_settings(self):
        if 1 <= self.WPAtype_spinbox.value() <= 2:
            self.set_security_type_text('WPA')
            if 8 <= len(self.editPasswordAP.text()) <= 63 and is_ascii(str(self.editPasswordAP.text())):
                self.editPasswordAP.setStyleSheet(
                    "QLineEdit { border: 1px solid green;}")
            else:
                self.editPasswordAP.setStyleSheet(
                    "QLineEdit { border: 1px solid red;}")
            self.wpa_pairwiseCB.setEnabled(True)
            if self.WPAtype_spinbox.value() == 2:
                self.set_security_type_text('WPA2')
        if self.WPAtype_spinbox.value() == 0:
            self.set_security_type_text('WEP')
            if (len(self.editPasswordAP.text()) == 5 or len(self.editPasswordAP.text()) == 13) and \
                    is_ascii(str(self.editPasswordAP.text())) or (len(self.editPasswordAP.text()) == 10 or len(self.editPasswordAP.text()) == 26) and \
                    is_hexadecimal(str(self.editPasswordAP.text())):
                self.editPasswordAP.setStyleSheet(
                    "QLineEdit { border: 1px solid green;}")
            else:
                self.editPasswordAP.setStyleSheet(
                    "QLineEdit { border: 1px solid red;}")
            self.wpa_pairwiseCB.setEnabled(False)

    def set_security_type_text(self, string=str):
        self.lb_type_security.setText(string)
        self.lb_type_security.setFixedWidth(60)
        self.lb_type_security.setStyleSheet("QLabel {border-radius: 2px;"
                                            "padding-left: 10px; background-color: #3A3939; color : silver; } "
                                            "QWidget:disabled{ color: #404040;background-color: #302F2F; } ")

    @classmethod
    def getInstance(cls):
        return cls.instances[0]
