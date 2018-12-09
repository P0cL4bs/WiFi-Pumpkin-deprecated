from core.config.globalimport import *
from core.utils import *
from os import (
    system,path,getcwd,
    popen,listdir,mkdir,chown
)
from shutil import move
from pwd import getpwnam
from grp import getgrnam
from core.widgets.customiseds import AutoGridLayout
from core.wirelessmode import *
from json import dumps,loads
from core.utility.threads import ProcessHostapd,ThRunDhcp,ProcessThread
from core.widgets.default.uimodel import *
from core.widgets.default.SessionConfig import *
from datetime import datetime


class WirelessModeController(QtGui.QTableWidget):

    def __init__(self, parent, **kwargs):
        super(WirelessModeController,self).__init__(parent)
        self.parent = parent
        self.setHidden(True) # hide widget on home
        self.FSettings = SuperSettings.getInstance()
        self.SessionsAP = loads(str(self.FSettings.Settings.get_setting('accesspoint', 'sessions')))
        self.currentSessionID = self.parent.currentSessionID
        self.SettingsAP = self.parent.SettingsAP
        self.SessionConfig = SessionConfig.instances[0]

    @property
    def Activated(self):
        return self.Settings.getActiveMode

    @property
    def ActiveReactor(self):
        return self.Settings.getActiveMode.reactor

    @property
    def Settings(self):
        return AccessPointSettings.instances[0]

    def Start(self):
        ''' start Access Point and settings plugins  '''
        if len(self.Settings.WLANCard.currentText()) == 0:
            return QtGui.QMessageBox.warning(self, 'Error interface ', 'Network interface is not found')
        if not type(self.Activated.get_soft_dependencies()) is bool: return

        # check if interface has been support AP mode (necessary for hostapd)
        if self.FSettings.Settings.get_setting('accesspoint', 'check_support_ap_mode', format=bool):
            if not 'AP' in Refactor.get_supported_interface(self.Settings.WLANCard.currentText())['Supported']:
                return QtGui.QMessageBox.warning(self, 'No Network Supported failed',
                                                 "<strong>failed AP mode: warning interface </strong>, the feature "
                                                 "Access Point Mode is Not Supported By This Device -><strong>({})</strong>.<br><br>"
                                                 "Your adapter does not support for create Access Point Network."
                                                 " ".format(self.Settings.WLANCard.currentText()))

        # check connection with internet
        #self.interfacesLink = Refactor.get_interfaces()
        # check if Wireless interface is being used
        if str(self.Settings.WLANCard.currentText()) == self.Activated.interfacesLink['activated'][0]:
            iwconfig = Popen(['iwconfig'], stdout=PIPE, shell=False, stderr=PIPE)
            for line in iwconfig.stdout.readlines():
                if str(self.Settings.WLANCard.currentText()) in line:
                    return QtGui.QMessageBox.warning(self, 'Wireless interface is busy',
                                                     'Connection has been detected, this {} is joined the correct Wi-Fi network'
                                                     ' : Device or resource busy\n{}\nYou may need to another Wi-Fi USB Adapter'
                                                     ' for create AP or try use with local connetion(Ethernet).'.format(
                                                         str(self.Settings.WLANCard.currentText()), line))
        # check if using ethernet or wireless connection
        print('[*] Configuring {}...'.format(self.Activated.Name))
        self.parent.SettingsEnable['AP_iface'] = str(self.Settings.WLANCard.currentText())
        set_monitor_mode(self.parent.SettingsEnable['AP_iface']).setDisable()
        if self.Activated.interfacesLink['activated'][1] == 'ethernet' or self.Activated.interfacesLink['activated'][1] == 'ppp' \
                or self.Activated.interfacesLink['activated'][0] == None:  # allow use without internet connection
            # change Wi-Fi state card
            Refactor.kill_procInterfaceBusy()  # killing network process
            try:
                check_output(['nmcli', 'radio', 'wifi', "off"])  # old version
            except Exception:
                try:
                    check_output(['nmcli', 'nm', 'wifi', "off"])  # new version
                except Exception as error:
                    return QtGui.QMessageBox.warning(self, 'Error nmcli', str(error))
            finally:
                call(['rfkill', 'unblock', 'wifi'])

        self.Activated.Start()
        self.Settings.setEnabled(False)
        return None


    def Stop(self):
        self.Settings.setEnabled(True)




class APStatus(HomeDisplay):
    Name = "AP Status"
    ID = "APStatus"
    ''' dashboard  infor Acccess Point '''
    def __init__(self,parent=0):
        super(APStatus, self).__init__(parent)
        self.timer = QtCore.QTimer()
        self.split_window = QtGui.QHBoxLayout()

        guageWindow = QtGui.QGridLayout()
        self.currentThreadLabel = QtGui.QLabel('0')
        currentthread = self.create_info_box('CURRENT THREADS', 'infor',
            self.currentThreadLabel)

        self.sectionTimeLabel = QtGui.QLabel('00:00')
        currentTime = self.create_info_box('UPTIME', 'infor', self.sectionTimeLabel)
        guageWindow.addLayout(currentthread, 1, 1)
        guageWindow.addLayout(currentTime, 0, 1)

        self.AP_name = QtGui.QLabel(self.FSettings.Settings.get_setting('accesspoint', 'ssid'))
        self.AP_BSSID = QtGui.QLabel(self.FSettings.Settings.get_setting('accesspoint', 'bssid'))
        self.AP_Channel = QtGui.QLabel(self.FSettings.Settings.get_setting('accesspoint', 'channel'))
        self.AP_NetworkApdater = QtGui.QLabel(self.FSettings.Settings.get_setting('accesspoint', 'interfaceAP'))
        self.AP_ROUTER = QtGui.QLabel(self.FSettings.Settings.get_setting('dhcp', 'router'))
        self.AP_DHCP_range = QtGui.QLabel(self.FSettings.Settings.get_setting('dhcp', 'range'))
        self.AP_Security  = QtGui.QLabel('')
        self.update_security_label(self.FSettings.Settings.get_setting('accesspoint', 'enable_Security', format=bool))

        self.group_AccessPoint  = QtGui.QGroupBox()
        self.form_window        = AutoGridLayout()
        self.form_window.setSpacing(10)
        self.group_AccessPoint.setTitle('Access Point')
        self.form_window.addNextWidget(QtGui.QLabel('AP Name:'))
        self.form_window.addNextWidget(self.AP_name)
        self.form_window.addNextWidget(QtGui.QLabel('BSSID:'))
        self.form_window.addNextWidget(self.AP_BSSID)
        self.form_window.addNextWidget(QtGui.QLabel('Channel:'))
        self.form_window.addNextWidget(self.AP_Channel)
        self.form_window.addNextWidget(QtGui.QLabel('Network Adapter:'))
        self.form_window.addNextWidget(self.AP_NetworkApdater)
        self.form_window.addNextWidget(QtGui.QLabel('Router:'))
        self.form_window.addNextWidget(self.AP_ROUTER)
        self.form_window.addNextWidget(QtGui.QLabel('DHCP:'))
        self.form_window.addNextWidget(self.AP_DHCP_range)
        self.form_window.addNextWidget(QtGui.QLabel('Security Password:'))
        self.form_window.addNextWidget(self.AP_Security)
        self.form_window.addItem(QtGui.QSpacerItem(40, 10, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding))
        self.group_AccessPoint.setLayout(self.form_window)

        self.split_window.addWidget(self.group_AccessPoint)
        self.split_window.addLayout(guageWindow)
        self.mainlayout.addLayout(self.split_window)

    def update_labels(self):
        self.AP_name.setText(self.FSettings.Settings.get_setting('accesspoint', 'ssid'))
        self.AP_BSSID.setText(self.FSettings.Settings.get_setting('accesspoint', 'bssid'))
        self.AP_Channel.setText(self.FSettings.Settings.get_setting('accesspoint', 'channel'))
        self.AP_NetworkApdater.setText(self.FSettings.Settings.get_setting('accesspoint', 'interfaceAP'))
        self.AP_ROUTER.setText(self.FSettings.Settings.get_setting('dhcp', 'router'))
        self.AP_DHCP_range.setText(self.FSettings.Settings.get_setting('dhcp', 'range'))
        self.update_security_label(self.FSettings.Settings.get_setting('accesspoint', 'enable_Security', format=bool))

    def start_timer(self):
        self.start_time_conut = datetime.now()
        self.update_timer()
        self.timer.timeout.connect(self.tick_timer)
        self.timer.start(1000)

    def update_timer(self):
        self.end_time_count = datetime.now()
        self.sectionTimeLabel.setText(self.strfdelta(
            (self.end_time_count - self.start_time_conut),
            '{hours} hs {minutes} mins'))
        self.currentThreadLabel.setText(self.FSettings.Settings.get_setting('runningconfig', 'totalthread'))

    def strfdelta(self, tdelta, fmt):
        # https://stackoverflow.com/questions/8906926/formatting-python-timedelta-objects
        d = {"D": tdelta.days}
        d["hours"], rem = divmod(tdelta.seconds, 3600)
        d["minutes"], d["seconds"] = divmod(rem, 60)
        return fmt.format(**d)

    def tick_timer(self):
        self.update_timer()

    def stop_timer(self):
        self.timer.stop()
        self.sectionTimeLabel.setText('00:00')
        self.currentThreadLabel.setText('0')

    def update_security_label(self, bool):
        if bool:
            self.AP_Security.setText('[ON]')
            self.AP_Security.setStyleSheet('QLabel {  color : green; }')
        else:
            self.AP_Security.setText('[OFF]')
            self.AP_Security.setStyleSheet('QLabel {  color : #df1f1f; }')

    def create_info_box(self, labelText, objectName, valueLabel):
        infoBox = QtGui.QVBoxLayout()
        infoBox.setSpacing(0)
        label = QtGui.QLabel(labelText)
        label.setObjectName('label')
        valueLabel.setAlignment(QtCore.Qt.AlignCenter)
        valueLabel.setObjectName(objectName)
        infoBox.addWidget(label)
        infoBox.addWidget(valueLabel)
        return infoBox


class AccessPointSettings(CoreSettings):
    Name = "Access Point"
    ID = "Wireless"
    Category = "Wireless"
    instances=[]
    def __init__(self,parent):
        super(AccessPointSettings,self).__init__(parent)
        self.__class__.instances.append(weakref.proxy(self))
        self.setMaximumWidth(600)
        self.__modelist = [mode(self.parent) for mode in WirelessMode.Mode.__subclasses__()]

        self.setCheckable(False)
        self.get_interfaces = Refactor.get_interfaces()
        self.btrn_refresh = QtGui.QPushButton("Requery")
        self.btrn_refresh.setIcon(QtGui.QIcon('icons/refresh.png'))
        self.btrn_refresh.setFixedWidth(200)
        self.btrn_refresh.clicked.connect(self.set_interface_wireless)
        self.WLANCard = QtGui.QComboBox()
        self.GroupAdapter = QtGui.QGroupBox()
        self.layoutNetworkAd = QtGui.QHBoxLayout()
        interfaces = self.get_interfaces['all']

        wireless = []
        for iface in interfaces:
            if search('wl', iface):
                wireless.append(iface)
        self.WLANCard.addItems(wireless)
        interface = self.FSettings.Settings.get_setting('accesspoint', 'interfaceAP')
        if interface != 'None' and interface in self.get_interfaces['all']:
            self.WLANCard.setCurrentIndex(wireless.index(interface))

        self.btrn_find_Inet = QtGui.QPushButton("Find Network Connection")
        self.btrn_find_Inet.setIcon(QtGui.QIcon('icons/router2.png'))
        self.btrn_find_Inet.clicked.connect(self.check_NetworkConnection)
        self.btrn_find_Inet.setFixedWidth(220)
        self.GroupAdapter.setTitle('Network Adapter')
        self.layoutNetworkAd.addWidget(self.WLANCard)
        self.layoutNetworkAd.addWidget(self.btrn_refresh)
        self.layoutNetworkAd.addWidget(self.btrn_find_Inet)
        self.GroupAdapter.setLayout(self.layoutNetworkAd)
        self.GroupAdapter.show()
        self.ModeGroup = QtGui.QButtonGroup()
        self.ModeSelection = QtGui.QGroupBox()
        self.ModeSelectionLayout = QtGui.QVBoxLayout()
        self.ModeSelection.setLayout(self.ModeSelectionLayout)
        self.ModeSelection.setTitle("Wireless Operation Mode")
        self.ModeList = {}
        
        for mode in self.__modelist:
            setattr(self.__class__, mode.ID, mode)
            self.ModeGroup.addButton(mode.controlui)
            if ((mode.ID  != 'Static') and not mode.checkifHostapdBinaryExist()):
                mode.controlui.setEnabled(False)
            self.ModeSelectionLayout.addWidget(mode.controlui)
        # Initialize WLAN Settings


        self.WLayout = QtGui.QGroupBox()
        self.WLayout.setTitle("Access Point")
        self.WLayout.setFixedWidth(260)
        self.WLGrid = QtGui.QGridLayout()
        self.WLayout.setLayout(self.WLGrid)
        self.EditSSID = QtGui.QLineEdit()
        self.BtnRandomSSID = QtGui.QPushButton()
        self.BtnRandomSSID.setIcon(QtGui.QIcon('icons/refresh.png'))
        self.BtnRandomSSID.clicked.connect(self.setAP_essid_random)
        self.EditBSSID = QtGui.QLineEdit()
        self.EditChannel = QtGui.QSpinBox()
        self.EditChannel.setMaximum(11)
        self.EditChannel.setFixedWidth(10)
        self.EditChannel.setMinimum(0)

        self.EditSSID.textChanged.connect(self.saveEventTextChangeSSID)

        self.WLGrid.addWidget(QtGui.QLabel("SSID:"), 0, 0)
        self.WLGrid.addWidget(self.EditSSID, 0, 1)
        self.WLGrid.addWidget(QtGui.QLabel("BSSID:"), 1, 0)
        self.WLGrid.addWidget(self.EditBSSID, 1, 1)
        self.WLGrid.addWidget(self.BtnRandomSSID, 1, 2)
        self.WLGrid.addWidget(QtGui.QLabel("Channel:"), 2, 0)
        self.WLGrid.addWidget(self.EditChannel, 2, 1)

        self.EditSSID.setText(self.FSettings.Settings.get_setting('accesspoint', 'ssid'))
        self.EditBSSID.setText(self.FSettings.Settings.get_setting('accesspoint', 'bssid'))
        self.EditChannel.setValue(self.FSettings.Settings.get_setting('accesspoint', 'channel', format=int))
        self.layout.addWidget(self.WLayout)
        self.layout.addWidget(self.GroupAdapter)
        self.layout.addWidget(self.ModeSelection)

    def saveEventTextChangeSSID(self):
        ''' save ssid name in config.ini'''
        self.FSettings.Settings.set_setting('accesspoint', 'ssid',self.EditSSID.text())

    def ModelistChanged(self,mode,widget):
        pass
    @property
    def getActiveMode(self):
        for mode in self.__modelist:
            if mode.controlui.isChecked():
                return mode

    @property
    def getInstances(self):
        return self.instances
    def setAP_essid_random(self):
        ''' set random mac 3 last digits  '''
        prefix = []
        for item in [x for x in str(self.EditBSSID.text()).split(':')]:
            prefix.append(int(item,16))
        self.EditBSSID.setText(Refactor.randomMacAddress([prefix[0],prefix[1],prefix[2]]).upper())

    def set_interface_wireless(self):
        ''' get all wireless interface available '''
        self.WLANCard.clear()
        self.btrn_refresh.setEnabled(False)
        ifaces = Refactor.get_interfaces()['all']
        QtCore.QTimer.singleShot(3000, lambda : self.add_avaliableIterfaces(ifaces))
        self.deleteObject(ifaces)
    def add_avaliableIterfaces(self,ifaces):
        for index,item in enumerate(ifaces):
            if search('wl', item):
                self.WLANCard.addItem(ifaces[index])
        return self.btrn_refresh.setEnabled(True)
    def check_NetworkConnection(self):
        ''' update inferfaces '''
        self.btrn_find_Inet.setEnabled(False)
        interfaces = Refactor.get_interfaces()
        self.parent.set_StatusConnected_Iface(False,'checking...',check=True)
        QtCore.QTimer.singleShot(3000, lambda: self.set_backgroud_Network(interfaces))
    def set_backgroud_Network(self,get_interfaces):
        ''' check interfaces on background '''
        if get_interfaces['activated'][0] != None:
            self.InternetShareWiFi = True
            self.btrn_find_Inet.setEnabled(True)
            return self.parent.set_StatusConnected_Iface(True, get_interfaces['activated'][0])
        self.InternetShareWiFi = False
        self.btrn_find_Inet.setEnabled(True)
        return self.parent.set_StatusConnected_Iface(False,'')
    def setAP_essid_random(self):
        ''' set random mac 3 last digits  '''
        prefix = []
        for item in [x for x in str(self.EditBSSID.text()).split(':')]:
            prefix.append(int(item,16))
        self.EditBSSID.setText(Refactor.randomMacAddress([prefix[0],prefix[1],prefix[2]]).upper())
    def configure_network_AP(self):
        ''' configure interface and dhcpd for mount Access Point '''
        self.DHCP = self.Settings.DHCP.conf
        self.SettingsEnable['PortRedirect'] = self.FSettings.Settings.get_setting('settings','redirect_port')
        self.SettingsAP = {
        'interface':
            [
                'ifconfig %s up'%(self.SettingsEnable['AP_iface']),
                'ifconfig %s %s netmask %s'%(self.SettingsEnable['AP_iface'],self.DHCP['router'],self.DHCP['netmask']),
                'ifconfig %s mtu 1400'%(self.SettingsEnable['AP_iface']),
                'route add -net %s netmask %s gw %s'%(self.DHCP['subnet'],
                self.DHCP['netmask'],self.DHCP['router'])
            ],
        'kill':
            [
                'iptables --flush',
                'iptables --table nat --flush',
                'iptables --delete-chain',
                'iptables --table nat --delete-chain',
                'ifconfig %s 0'%(self.SettingsEnable['AP_iface']),
                'killall dhpcd 2>/dev/null',
            ],
        'hostapd':
            [
                'interface={}\n'.format(str(self.Settings.WLANCard.currentText())),
                'ssid={}\n'.format(str(self.EditApName.text())),
                'channel={}\n'.format(str(self.EditChannel.value())),
                'bssid={}\n'.format(str(self.EditBSSID.text())),
            ],
        'dhcp-server':
            [
                'authoritative;\n',
                'default-lease-time {};\n'.format(self.DHCP['leasetimeDef']),
                'max-lease-time {};\n'.format(self.DHCP['leasetimeMax']),
                'subnet %s netmask %s {\n'%(self.DHCP['subnet'],self.DHCP['netmask']),
                'option routers {};\n'.format(self.DHCP['router']),
                'option subnet-mask {};\n'.format(self.DHCP['netmask']),
                'option broadcast-address {};\n'.format(self.DHCP['broadcast']),
                'option domain-name \"%s\";\n'%(str(self.EditApName.text())),
                'option domain-name-servers {};\n'.format('8.8.8.8'),
                'range {};\n'.format(self.DHCP['range'].replace('/',' ')),
                '}',
            ],
        }
        print('[*] Enable forwarding in iptables...')
        Refactor.set_ip_forward(1)
        # clean iptables settings
        for line in self.SettingsAP['kill']: exec_bash(line)
        # set interface using ifconfig
        for line in self.SettingsAP['interface']: exec_bash(line)
        # check if dhcp option is enabled.
        if self.FSettings.Settings.get_setting('accesspoint','dhcp_server',format=bool):
            with open(C.DHCPCONF_PATH,'w') as dhcp:
                for line in self.SettingsAP['dhcp-server']:dhcp.write(line)
                dhcp.close()
                if not path.isdir('/etc/dhcp/'): mkdir('/etc/dhcp')
                move(C.DHCPCONF_PATH, '/etc/dhcp/')



        