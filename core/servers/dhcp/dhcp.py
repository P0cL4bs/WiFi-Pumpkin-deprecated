from re import *
from netaddr import EUI
from core.config.globalimport import *
from core.widgets.customiseds import *
from core.widgets.default.uimodel import *
from core.utility.component import ControllerBlueprint
from isc_dhcp_leases.iscdhcpleases import IscDhcpLeases
from core.utility.threads import (ProcessThread)
from core.widgets.notifications import ServiceNotify

class DHCPServers(QtGui.QWidget,ComponentBlueprint):
    Name = "Generic"
    ID = "Generic"
    haspref = False
    ExecutableFile=""
    def __init__(self,parent=0):
        super(DHCPServers,self).__init__()
        self.parent = parent
        self.FSettings = SuperSettings.getInstance()
        self.EditGateway = QtGui.QLineEdit(self)
        self.EditGateway.setFixedWidth(120)
        self.EditGateway.setHidden(True)  # disable Gateway
        self.controlui = QtGui.QRadioButton(self.Name)
        self.controlui.toggled.connect(partial(self.controlcheck, self.controlui))
        self.controlui.setChecked(self.FSettings.Settings.get_setting('dhcpserver', self.ID,format=bool))
        self.controlui.setObjectName(self.ID)
        self.DHCPConf = self.Settings.conf
    def controlcheck(self,object):
        self.FSettings.Settings.set_setting('dhcpserver', self.ID, self.controlui.isChecked())
    def prereq(self):
        dh, gateway = self.DHCPConf['router'], str(self.EditGateway.text())
        # dh, gateway = self.PumpSettingsTAB.getPumpkinSettings()['router'],str(self.EditGateway.text())
        if dh[:len(dh) - len(dh.split('.').pop())] == gateway[:len(gateway) - len(gateway.split('.').pop())]:
            return QtGui.QMessageBox.warning(self, 'DHCP Server settings',
                                             'The DHCP server check if range ip class is same.'
                                             'it works, but not share internet connection in some case.\n'
                                             'for fix this, You need change on tab (settings -> Class Ranges)'
                                             'now you have choose the Class range different of your network.')
    def Stop(self):
        self.shutdown()
        self.reactor.stop()

    def Start(self):
        self.prereq()
        self.Initialize()
        self.boot()

    @property
    def Settings(self):
        return DHCPSettings.instances[0]

    @property
    def commandargs(self):
        pass

    def boot(self):
        print self.command,self.commandargs
        self.reactor = ProcessThread({self.command: self.commandargs})
        self.reactor._ProcssOutput.connect(self.LogOutput)
        self.reactor.setObjectName(self.Name)  # use dns2proxy as DNS server

    @property
    def HomeDisplay(self):
        return DHCPClient.instances[0]

    @property
    def command(self):
        cmdpath = os.popen('which {}'.format(self.ExecutableFile)).read().split('\n')[0]
        if cmdpath:
            return cmdpath
        else:
            return None

    def get_mac_vendor(self,mac):
        ''' discovery mac vendor by mac address '''
        try:
            d_vendor = EUI(mac)
            d_vendor = d_vendor.oui.registration().org
        except:
            d_vendor = 'unknown mac'
        return d_vendor

    def add_data_into_QTableWidget(self,client):
        self.HomeDisplay.ClientTable.addNextWidget(client)

    def add_DHCP_Requests_clients(self,mac,user_info):
        self.parent.StationMonitor.addRequests(mac,user_info,True)

    def get_DHCP_Discover_clients(self,message):
        '''get infor client connected with AP '''
        self.APclients = {}
        if message['mac_addr'] not in self.HomeDisplay.ClientTable.APclients.keys():
            self.APclients[message['mac_addr']] = \
            {'IP': message['ip_addr'],
            'device': message['host_name'],
             'MAC': message['mac_addr'],
             'Vendors' : self.get_mac_vendor(message['mac_addr'])}

            self.add_DHCP_Requests_clients(message['mac_addr'],self.APclients[message['mac_addr']])
            self.add_data_into_QTableWidget(self.APclients)
            self.parent.connectedCount.setText(str(len(self.HomeDisplay.ClientTable.APclients.keys())))

    def get_DHCP_Requests_clients(self,data):
        ''' filter: data info sended DHCPD request '''
        self.APclients = {}
        if len(data) == 8:
            device = sub(r'[)|(]',r'',data[5])
            if len(device) == 0: device = 'unknown'
            if Refactor.check_is_mac(data[4]):
                if data[4] not in self.HomeDisplay.APclients.keys():
                    self.APclients[data[4]] = {'IP': data[2],
                    'device': device,'MAC': data[4],'Vendors' : self.get_mac_vendor(data[4])}
                    self.add_DHCP_Requests_clients(data[4],self.APclients[data[4]])
        elif len(data) == 9:
            device = sub(r'[)|(]',r'',data[6])
            if len(device) == 0: device = 'unknown'
            if Refactor.check_is_mac(data[5]):
                if data[5] not in self.HomeDisplay.ClientTable.APclients.keys():
                    self.APclients[data[5]] = {'IP': data[2],
                    'device': device,'MAC': data[5],'Vendors' : self.get_mac_vendor(data[5])}
                    self.add_DHCP_Requests_clients(data[5],self.APclients[data[5]])
        elif len(data) == 7:
            if Refactor.check_is_mac(data[4]):
                if data[4] not in self.HomeDisplay.ClientTable.APclients.keys():
                    leases = IscDhcpLeases(C.DHCPLEASES_PATH)
                    hostname = None
                    try:
                        for item in leases.get():
                            if item.ethernet == data[4]:
                                hostname = item.hostname
                        if hostname == None:
                            item = leases.get_current()
                            hostname = item[data[4]]
                    except:
                        hostname = 'unknown'
                    if hostname == None or len(hostname) == 0:hostname = 'unknown'
                    self.APclients[data[4]] = {'IP': data[2],'device': hostname,
                                               'MAC': data[4], 'Vendors': self.get_mac_vendor(data[4])}
                    self.add_DHCP_Requests_clients(data[4],self.APclients[data[4]])
        if self.APclients != {}:
            self.add_data_into_QTableWidget(self.APclients)
            self.parent.connectedCount.setText(str(len(self.HomeDisplay.ClientTable.APclients.keys())))



class DHCPSettings(CoreSettings):
    Name = "WP DHCP"
    ID = "DHCP"
    ConfigRoot = "dhcp"
    Category = "DHCP"
    instances=[]

    def __init__(self,parent=0):
        super(DHCPSettings,self).__init__(parent)
        self.__class__.instances.append(weakref.proxy(self))
        self.setCheckable(False)
        self.setFixedWidth(400)
        self.dhmode = [mod(parent) for mod in DHCPServers.__subclasses__()]
        self.modoption = QtGui.QFormLayout()
        self.modegroup = QtGui.QButtonGroup()

        for dhmode in self.dhmode:
            self.modoption.addRow(dhmode.controlui)
            self.modegroup.addButton(dhmode.controlui)
        self.layoutDHCP = QtGui.QFormLayout()
        self.layoutbuttons = QtGui.QHBoxLayout()
        self.btnDefault = QtGui.QPushButton('Default')
        self.btnSave = QtGui.QPushButton('save settings')
        self.btnSave.setIcon(QtGui.QIcon('icons/export.png'))
        self.btnDefault.setIcon(QtGui.QIcon('icons/settings.png'))
        self.btnDefault.clicked.connect(self.setdefaultSettings)
        self.btnSave.clicked.connect(self.setChangeSettings)


        self.dhcpClassIP = QtGui.QComboBox()
        self.EditGateway = QtGui.QLineEdit(self)
        self.EditGateway.setFixedWidth(120)
        self.EditGateway.setHidden(True)  # disable Gateway

        self.classtypes = ['Class-A-Address', 'Class-B-Address', 'Class-C-Address', 'Class-Custom-Address']
        for types in self.classtypes:
            if 'Class-{}-Address'.format(self.FSettings.Settings.get_setting(self.ConfigRoot, 'classtype')) in types:
                self.classtypes.remove(types), self.classtypes.insert(0, types)
        self.dhcpClassIP.addItems(self.classtypes)
        self.leaseTimeDef = QtGui.QLineEdit(self.FSettings.Settings.get_setting(self.ConfigRoot, 'leasetimeDef'))
        self.leaseTimeMax = QtGui.QLineEdit(self.FSettings.Settings.get_setting(self.ConfigRoot, 'leasetimeMax'))
        self.netmask = QtGui.QLineEdit(self.FSettings.Settings.get_setting(self.ConfigRoot, 'netmask'))
        self.range = QtGui.QLineEdit(self.FSettings.Settings.get_setting(self.ConfigRoot, 'range'))
        self.router = QtGui.QLineEdit(self.FSettings.Settings.get_setting(self.ConfigRoot, 'router'))
        self.subnet = QtGui.QLineEdit(self.FSettings.Settings.get_setting(self.ConfigRoot, 'subnet'))
        self.broadcast = QtGui.QLineEdit(self.FSettings.Settings.get_setting(self.ConfigRoot, 'broadcast'))
        self.dhcpClassIP.currentIndexChanged.connect(self.dhcpClassIPClicked)

        self.layoutDHCP.addRow(self.modoption)
        self.layoutDHCP.addRow('Class Ranges', self.dhcpClassIP)
        self.layoutDHCP.addRow('Default Lease time', self.leaseTimeDef)
        self.layoutDHCP.addRow('Max Lease time', self.leaseTimeMax)
        self.layoutDHCP.addRow('Subnet', self.subnet)
        self.layoutDHCP.addRow('Router', self.router)
        self.layoutDHCP.addRow('Netmask', self.netmask)
        self.layoutDHCP.addRow('Broadcaset Address', self.broadcast)
        self.layoutDHCP.addRow('DHCP IP-Range', self.range)

        self.updateconf()

        # layout add
        self.layoutbuttons.addWidget(self.btnSave)
        self.layoutbuttons.addWidget(self.btnDefault)
        self.layoutDHCP.addRow(self.layoutbuttons)
        self.layout.addLayout(self.layoutDHCP)

    def dhcpClassIPClicked(self,classIP):
        self.selected = str(self.dhcpClassIP.currentText())
        if 'class-Custom-Address' in self.selected: self.selected = 'dhcp'
        self.leaseTimeDef.setText(self.FSettings.Settings.get_setting(self.selected,'leasetimeDef'))
        self.leaseTimeMax.setText(self.FSettings.Settings.get_setting(self.selected,'leasetimeMax'))
        self.netmask.setText(self.FSettings.Settings.get_setting(self.selected,'netmask'))
        self.range.setText(self.FSettings.Settings.get_setting(self.selected,'range'))
        self.router.setText(self.FSettings.Settings.get_setting(self.selected,'router'))
        self.subnet.setText(self.FSettings.Settings.get_setting(self.selected,'subnet'))
        self.broadcast.setText(self.FSettings.Settings.get_setting(self.selected,'broadcast'))
        self.savesettingsDHCP()
        self.updateconf()
        

    def setdefaultSettings(self):
        self.dhcpClassIP.setCurrentIndex(self.classtypes.index('Class-A-Address'))
        self.leaseTimeDef.setText(self.FSettings.Settings.get_setting('dhcpdefault','leasetimeDef'))
        self.leaseTimeMax.setText(self.FSettings.Settings.get_setting('dhcpdefault','leasetimeMax'))
        self.netmask.setText(self.FSettings.Settings.get_setting('dhcpdefault','netmask'))
        self.range.setText(self.FSettings.Settings.get_setting('dhcpdefault','range'))
        self.router.setText(self.FSettings.Settings.get_setting('dhcpdefault','router'))
        self.subnet.setText(self.FSettings.Settings.get_setting('dhcpdefault','subnet'))
        self.broadcast.setText(self.FSettings.Settings.get_setting('dhcpdefault','broadcast'))
        self.updateconf()
        self.savesettingsDHCP()
        QtGui.QMessageBox.information(self, 'DHCP Settings', 'DHCP Server conf successfully restarted')

    def setChangeSettings(self):
        self.savesettingsDHCP()
        self.updateconf()
        QtGui.QMessageBox.information(self, 'DHCP Settings', 'DHCP configuration had been saved successfully')

    def savesettingsDHCP(self):
        self.all_geteway_check = []
        for types in self.classtypes:
            if not 'Class-Custom-Address' in types:
                self.all_geteway_check.append(self.FSettings.Settings.get_by_index_key(5,types))
        self.FSettings.Settings.set_setting(self.ConfigRoot,'classtype',str(self.dhcpClassIP.currentText()).split('-')[1])
        self.FSettings.Settings.set_setting(self.ConfigRoot,'leasetimeDef',str(self.leaseTimeDef.text()))
        self.FSettings.Settings.set_setting(self.ConfigRoot,'leasetimeMax',str(self.leaseTimeMax.text()))
        self.FSettings.Settings.set_setting(self.ConfigRoot,'netmask',str(self.netmask.text()))
        self.FSettings.Settings.set_setting(self.ConfigRoot,'range',str(self.range.text()))
        self.FSettings.Settings.set_setting(self.ConfigRoot,'router',str(self.router.text()))
        self.FSettings.Settings.set_setting(self.ConfigRoot,'subnet',str(self.subnet.text()))
        self.FSettings.Settings.set_setting(self.ConfigRoot,'broadcast',str(self.broadcast.text()))
        if not str(self.router.text()) in self.all_geteway_check:
            self.FSettings.Settings.set_setting(self.ConfigRoot,'classtype','Custom')
        self.btnSave.setEnabled(True)
    def updateconf(self):
        self.conf['leasetimeDef'] = str(self.leaseTimeDef.text())
        self.conf['leasetimeMax'] = str(self.leaseTimeMax.text())
        self.conf['subnet'] = str(self.subnet.text())
        self.conf['router'] = str(self.router.text())
        self.conf['netmask'] = str(self.netmask.text())
        self.conf['broadcast'] = str(self.broadcast.text())
        self.conf['range'] = str(self.range.text())

class DHCPClient(HomeDisplay):
    Name = "DHCP"
    ID = "DHCP"
    instances=[]
    def __init__(self,parent):
        super(DHCPClient,self).__init__(parent)
        self.__class__.instances.append(weakref.proxy(self))
        self.ClientTable = AutoTableWidget()
        self.THeaders = OrderedDict([('Devices', []),
                                     ('IP Address', []),
                                     ('Mac Address', []),
                                     ('Vendors', [])],
                                    )
        self.ClientTable.setRowCount(50)
        self.ClientTable.resizeRowsToContents()
        self.ClientTable.setSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        self.ClientTable.horizontalHeader().setStretchLastSection(True)
        self.ClientTable.setSelectionMode(QtGui.QAbstractItemView.NoSelection)
        self.ClientTable.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.ClientTable.verticalHeader().setVisible(False)
        self.ClientTable.setHorizontalHeaderLabels(self.THeaders.keys())
        self.ClientTable.verticalHeader().setDefaultSectionSize(23)
        self.ClientTable.horizontalHeader().resizeSection(3, 140)
        self.ClientTable.horizontalHeader().resizeSection(0, 140)
        self.ClientTable.horizontalHeader().resizeSection(2, 120)
        self.ClientTable.horizontalHeader().resizeSection(1, 120)
        self.ClientTable.setSortingEnabled(True)
        self.ClientTable.setObjectName('table_clients')


        self.donatelink = C.DONATE
        self.donateLabel = ServiceNotify(C.DONATE_TXT,title='Support development',
        link=self.donatelink,timeout=10000)
        # set main page Tool
        self.mainlayout.addWidget(self.donateLabel)
        self.mainlayout.addWidget(self.ClientTable)