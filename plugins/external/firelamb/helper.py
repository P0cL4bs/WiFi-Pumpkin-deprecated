#!/usr/bin/env python
# copyright of sandro gauci 2008
# hijack helper functions
def parseHeader(buff,type='response'):
    import re
    SEP = '\r\n\r\n'
    HeadersSEP = '\r*\n(?![\t\x20])'
    import logging
    log = logging.getLogger('parseHeader')
    if SEP in buff:
        header,body = buff.split(SEP,1)
    else:
        header = buff
        body = ''
    headerlines = re.split(HeadersSEP, header)
    
    if len(headerlines) > 1:
        r = dict()
        if type == 'response':
            _t = headerlines[0].split(' ',2)
            if len(_t) == 3:
                httpversion,_code,description = _t
            else:
                log.warn('Could not parse the first header line: %s' % `_t`)
                return r
            try:
                r['code'] = int(_code)
            except ValueError:
                return r
        elif type == 'request':
            _t = headerlines[0].split(' ',2)
            if len(_t) == 3:
                method,uri,httpversion = _t
                r['method'] = method
                r['uri'] = uri
                r['httpversion'] = httpversion
        else:
            log.warn('Could not parse the first header line: %s' % `_t`)
            return r  
        r['headers'] = dict()
        for headerline in headerlines[1:]:
            SEP = ':'
            if SEP in headerline:
                tmpname,tmpval = headerline.split(SEP,1)
                name = tmpname.lower().strip()
                val =  map(lambda x: x.strip(),tmpval.split(','))
            else:
                name,val = headerline.lower(),None
            r['headers'][name] = val
        r['body'] = body
        return r

def getdsturl(tcpdata):
        import logging
        log = logging.getLogger('getdsturl')
        p = parseHeader(tcpdata,type='request')
        if p is None:
                log.warn('parseHeader returned None')
                return
        if p.has_key('uri') and p.has_key('headers'):
            if p['headers'].has_key('host'):
                r = 'http://%s%s' % (p['headers']['host'][0],p['uri'])
                return r
            else:
                log.warn('seems like no host header was set')
        else:
                log.warn('parseHeader did not give us a nice return %s' % p)

def gethost(tcpdata):
    import logging
    log = logging.getLogger('getdsturl')
    p = parseHeader(tcpdata,type='request')
    if p is None:
            log.warn('parseHeader returned None')
            return
    if p.has_key('headers'):
        if p['headers'].has_key('host'):
            return p['headers']['host']

def getuseragent(tcpdata):
    import logging
    log = logging.getLogger('getuseragent')
    p = parseHeader(tcpdata,type='request')
    if p is None:
            log.warn('parseHeader returned None')
            return
    if p.has_key('headers'):
        if p['headers'].has_key('user-agent'):
            return p['headers']['user-agent']
        
def calcloglevel(options):
    logginglevel = 30
    if options.verbose is not None:
        if options.verbose >= 3:
            logginglevel = 10
        else:
            logginglevel = 30-(options.verbose*10)
    if options.quiet:
        logginglevel = 50
    return logginglevel

def getcookie(tcpdata):
	p = parseHeader(tcpdata,type='request')
	if p is None:
		return
	if p.has_key('headers'):
		if p['headers'].has_key('cookie'):
			return p['headers']['cookie']
