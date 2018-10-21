from core.config.globalimport import *

class ComponentBlueprint(object):
    Name = "GenericComponent"
    ID = "Generic"
    def __init__(self):
        super(ComponentBlueprint,self).__init__()
        self.reactor = None
        self.service = None

    def Initialize(self):
        """
        Initialise everything here
        :return:
        """
        pass
    def boot(self):
        """
        Thing you will need to do aftere initialization here
        :return:
        """
        pass
    def postBoot(self):
        """
        Things you do after boot here
        :return:
        """
        pass
    def shutdown(self):
        pass
    def LogOutput(self,data):
        print data
    def Start(self):
        self.PreBoot()
        self.Initialize()
        self.boot()
        self.PostBoot()
    def Stop(self):
        pass
    @property
    def Settings(self):
        pass

    def stupidthings(self):
        print "From Component Blueprint"
    def PreBoot(self):
        pass
    def PostBoot(self):
        pass


class ControllerBlueprint(object):
    def __init__(self):
        super(ControllerBlueprint,self).__init__()
    @property
    def Active(self):
        pass
    @property
    def ActiveReactor(self):
        pass
    @property
    def ActiveService(self):
        pass
    @property
    def Start(self):
        pass
    def Stop(self):
        pass
    def SaveLog(self):
        pass

    def LogOutput(self, data):
        pass

