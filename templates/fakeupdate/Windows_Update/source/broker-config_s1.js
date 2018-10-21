/*
Copyright (c) 2014, comScore Inc. All rights reserved.
version: 5.0.3
*/
COMSCORE.SiteRecruit.Broker.config = {
	version: "5.0.3",
	//TODO:Karl extend cookie enhancements to ie userdata
	testMode: false,
	// START 5.1.3
	cddsDomains: 'microsoftstore.com|windowsphone.com|xbox.com',
	cddsInProgress: 'cddsinprogress',
	domainSwitch: 'tracking3p',
	domainMatch: '([\\da-z\.-]+\.com)',
	delay: 0,
	// END 5.1.3
	
	// cookie settings
	cookie:{
		name: 'msresearch',
		path: '/',
		domain:  '.microsoft.com' ,
		duration: 90,
		rapidDuration: 0,
		expireDate: ''
	},
	thirdPartyOptOutCookieEnabled : false,
	
	// optional prefix for pagemapping's pageconfig file
	prefixUrl: "",
	
	//events
	Events: {
		beforeRecruit: function() {
		if(/microsoft\.com\/en-us\/download/i.test(window.location.toString())){
			if(/windowsmediaplayer|(microsoft|microsoftbusinesshub|xbox|windowsphone|windows|skype|login.live|microsoftvirtualacademy|microsoftvolumelicensing|microsoftstore|office)\.com/i.test(document.referrer) && document.referrer != ""){
				for(i=0; i<COMSCORE.SiteRecruit.Broker.config.mapping.length; i++){
					if(COMSCORE.SiteRecruit.Broker.config.mapping[i].c == "inv_c_3331mt_p105571867-1345.js"){
						COMSCORE.SiteRecruit.Broker.config.mapping[i].c = 'inv_c_p151121198-1345.js';
						var _currFreq = COMSCORE.SiteRecruit.Broker.config.mapping[i].f;
						var _newFreq = _currFreq * 0.03;
						COMSCORE.SiteRecruit.Broker.config.mapping[i].f = _newFreq.toFixed(5);
					}
			 	}
			}
		}
					}
	},
	
		mapping:[
	// m=regex match, c=page config file (prefixed with configUrl), f=frequency
	{m: '//[\\w\\.-]+/about((/)|(/((default)|(index))\\.((html?)|(aspx?)|(mspx))))?$', c: 'inv_c_3331mt2.js', f: 0.37, p: 0 	}
	,{m: '//[\\w\\.-]+/de-de/cloud/', c: 'inv_c_p73639549-Germany.js', f: 0.5, p: 0 	}
	,{m: '//(?!privacy)[\\w\\.-]*/de-de/(default\\.aspx|$)', c: 'inv_c_p162091074-Germany-HP.js', f: 0.3244, p: 1 	}
	,{m: '//[\\w\\.-]+/de-de/download', c: 'inv_c_p162095591-DLC-DE-DE.js', f: 0.0389, p: 1 	}
	,{m: '//[\\w\\.-]+/de-de/phone', c: 'inv_c_p291491624-DE-DE-Phone.js', f: 0.5, p: 1 	}
	,{m: '//[\\w\\.-]+/de-de/windows/compatibility/CompatCenter/.*', c: 'inv_c_p176052898-DE-DE.js', f: 0.1306, p: 4 	}
	,{m: '//[\\w\\.-]+/enable/', c: 'inv_c_p174575219-Accessibility.js', f: 0.5, p: 0 	}
	,{m: '//(?!privacy)[\\w\\.-]+/en-ca/($|default\\.aspx$)', c: 'inv_c_p162091074-EN-CA_HP.js', f: 0.5, p: 1 	}
	,{m: '//[\\w\\.-]+/en-ca/download', c: 'inv_c_p162095591-DLC-EN-CA.js', f: 0.5, p: 1 	}
	,{m: '//(?!privacy)[\\w\\.-]+/en-gb/(default\\.aspx|$)', c: 'inv_c_p162091074-EN-GB_HP.js', f: 0.5, p: 0 	}
	,{m: '//[\\w\\.-]+/en-gb/download', c: 'inv_c_p162095591-DLC-EN-GB.js', f: 0.2451, p: 1 	}
	,{m: '//[\\w\\.-]+/en-gb/laptop', c: 'inv_c_p291491624-EN-GB-Laptop.js', f: 0.5, p: 1 	}
	,{m: '//[\\w\\.-]+/en-gb/phone', c: 'inv_c_p291491624-EN-GB-Phone.js', f: 0.5, p: 1 	}
	,{m: '//[\\w\\.-]+/en-gb/tablet', c: 'inv_c_p291491624-EN-GB-Tablet.js', f: 0.5, p: 1 	}
	,{m: '//[\\w\\.-]+/en-gb/windows/compatibility/CompatCenter/.*', c: 'inv_c_p176052898-EN-GB.js', f: 0.4514, p: 0 	}
	,{m: '//(?!privacy)[\\w\\.-]+/en-ie/($|default\\.aspx$)', c: 'inv_c_p55836780-EN-IRELAND_HP.js', f: 0.5, p: 1 	}
	,{m: '//(?!privacy)[\\w\\.-]+/en-in/($|default\\.aspx$)', c: 'inv_c_p162091074-EN-IN.js', f: 0.1888, p: 1 	}
	,{m: '//[\\w\\.-]+/en-in/download', c: 'inv_c_p162095591-DLC-EN-IN.js', f: 0.3585, p: 1 	}
	,{m: '//(www|wwwstaging)[\\w\\.-]*/en-us/(default\\.aspx)?$', c: 'inv_c_p38796305-EN-US-PREVIEW.js', f: 0.15, p: 1 	}
	,{m: '//[\\w\\.-]+/(en-us/download)|(download/(en/|.*?displaylang=en))', c: 'inv_c_3331mt_p105571867-1345.js', f: 0.15, p: 1 	}
	,{m: '//[\\w\\.-]+/en-us/home/beta_a\\.html$', c: 'inv_c_p151121257-EN-US-HOME-BETA-A.js', f: 0.3, p: 0 	}
	,{m: '//[\\w\\.-]+/en-us/home/beta_b\\.html$', c: 'inv_c_p151121257-EN-US-HOME-BETA_B.js', f: 0.3, p: 0 	}
	,{m: '//[\\w\\.-]+/en-us/laptop', c: 'inv_c_p291491624-US-Laptop.js', f: 0.5, p: 0 	}
	,{m: '//[\\w\\.-]+/en-us/phone', c: 'inv_c_p291491624-US-Phone.js', f: 0.43, p: 0 	}
	,{m: '//[\\w\\.-]+/en-us/powerbi/', c: 'inv_c_p218292485_2694.js', f: 0.15, p: 1 	}
	,{m: '//[\\w\\.-]+/en-us/premiumlaptop', c: 'inv_c_p291491624-US-Prem-Laptop.js', f: 0.5, p: 0 	}
	,{m: '//[\\w\\.-]+/en-us/search/DownloadsDrillInResults\\.aspx', c: 'inv_c_p17676013-Search-US-2698.js', f: 0.15, p: 1 	}
	,{m: '//[\\w\\.-]+/en-us/search/GeneralInfoDrillInResults\\.aspx', c: 'inv_c_p17676013-Search-US-2699.js', f: 0.15, p: 1 	}
	,{m: '//[\\w\\.-]+/en-us/search/SupportDrillInResults\\.aspx', c: 'inv_c_p17676013-Search-US-2697.js', f: 0.15, p: 1 	}
	,{m: '//[\\w\\.-]+/en-us/search/WinAppsDrillInResults\\.aspx', c: 'inv_c_p17676013-Search-US-2700.js', f: 0.15, p: 1 	}
	,{m: '//[\\w\\.-]+/en-us/(search|newsearch)/(result|results)\\.aspx', c: 'inv_c_p17676013-Search-US-76.js', f: 0.2113, p: 1 	}
	,{m: '//[\\w\\.-]+/en-us/server-cloud/', c: 'inv_c_p218292485-2197.js', f: 0.5, p: 0 	}
	,{m: '//[\\w\\.-]+/en-us/sqlserver', c: 'inv_c_p218292485-SQL-2198.js', f: 0.5, p: 1 	}
	,{m: '//[\\w\\.-]+/en-us/tablet', c: 'inv_c_p291491624-US-Tablet.js', f: 0.5, p: 1 	}
	,{m: '//[\\w\\.-]+/en-us/windows/compatibility/CompatCenter/.*', c: 'inv_c_p176052898-EN-US.js', f: 0.0193, p: 4 	}
	,{m: '//[\\w\\.-]+/en-us/windows/enterprise/', c: 'inv_c_p38361073-DDS.js', f: 0.5, p: 0 	}
	,{m: '//[\\w\\.-]+/es-es/windows/compatibility/CompatCenter/.*', c: 'inv_c_p234872763-ES-ES.js', f: 0.1734, p: 4 	}
	,{m: '//(?!privacy)[\\w\\.-]+/fr-ca/($|default\\.aspx)', c: 'inv_c_p162091074-FR-CA-HP.js', f: 0.5, p: 2 	}
	,{m: '//[\\w\\.-]+/fr-ca/download', c: 'inv_c_p162095591-DLC-FR-CA.js', f: 0.5, p: 1 	}
	,{m: '//(www|wwwstaging)[\\w\\.-]*/fr-fr/(default\\.aspx|$)', c: 'inv_c_p162091074-FR-FR.js', f: 0.5, p: 1 	}
	,{m: '//[\\w\\.-]+/fr-fr/download', c: 'inv_c_p162095591-DLC-FR-FR.js', f: 0.088, p: 1 	}
	,{m: '//[\\w\\.-]+/fr-fr/phone', c: 'inv_c_p291491624-FR-FR-Phone.js', f: 0.5, p: 1 	}
	,{m: '//[\\w\\.-]+/fr-fr/tablet', c: 'inv_c_p291491624-FR-FR-Tablet.js', f: 0.5, p: 1 	}
	,{m: '//[\\w\\.-]+/fr-fr/windows/compatibility/CompatCenter/.*', c: 'inv_c_p176052898-FR-FR.js', f: 0.2433, p: 4 	}
	,{m: '//[\\w\\.-]+/government/en-au/public-services', c: 'inv_c_p233386094-2329.js', f: 0.5, p: 1 	}
	,{m: '//[\\w\\.-]+/it-it/phone', c: 'inv_c_p291491624-IT-IT-Phone.js', f: 0.43, p: 2 	}
	,{m: '//[\\w\\.-]+/it-it/windows/compatibility/CompatCenter/.*', c: 'inv_c_p176052898-IT-IT.js', f: 0.5, p: 2 	}
	,{m: '//[\\w\\.-]+/ja-jp/atlife', c: 'inv_c_p15466742-JA-JP-ATLIFE.js', f: 0.0068, p: 1 	}
	,{m: '//(wwwstaging|www\\.microsoft\\.com)/ja-jp/(default\\.aspx)?$', c: 'inv_c_p15466742-Japan-HP.js', f: 0.3045, p: 1 	}
	,{m: '//[\\w\\.-]+/ja-jp/download', c: 'inv_c_p162095591-DLC-Japan.js', f: 0.025, p: 1 	}
	,{m: '//[\\w\\.-]+/ja-jp/server-cloud', c: 'inv_c_JA-p15466742-server-cloud-WS.js', f: 0.1002, p: 0 	}
	,{m: '//[\\w\\.-]+/ja-jp/tablet', c: 'inv_c_p291491624-JA-JP-Tablet.js', f: 0.5, p: 1 	}
	,{m: '//[\\w\\.-]+/ja-jp/windows/compatibility/CompatCenter/.*', c: 'inv_c_p176052898-JA-JP.js', f: 0.4779, p: 4 	}
	,{m: '//[\\w\\.-]+/japan/windows(/(?!(downloads/ie/au\\.mspx)|(downloads/ie/iedelete\\.mspx))|$)', c: 'inv_c_JA-p15466742-p37131508-windows.js', f: 0.0544, p: 1 	}
]
};

var  wtExpId =999;
var SRtempCookie = document.cookie.toString();

//ClickTaleData
	function checkClickTaleData(){
		if(intMax > 0){
			intMax --;			
			try{
				if(ClickTaleGetPID() && ClickTaleGetSID() && ClickTaleGetUID()){
					COMSCORE.SiteRecruit._halt = false;
					COMSCORE.SiteRecruit.Broker.run();
					clearClickTaleData();
				}
			}catch(err){	}
		}else{
			clearClickTaleData();
		}
	}

	function clearClickTaleData() {
		window.clearInterval(CTDInterval);
	}

	if(/en-us\/(laptop|phone|premiumlaptop|tablet)/i.test(document.location.toString()) && document.cookie.indexOf('msresearch') == -1 ){
		COMSCORE.SiteRecruit._halt = true;
		var intMax = 15;
		var CTDInterval = window.setInterval('checkClickTaleData()', '1000');
	}

// START 5.1.3
function _set_SessionCookie(_name, _val) {	  
	if (_name == COMSCORE.SiteRecruit.Broker.config.domainSwitch) {
		var r = new RegExp(COMSCORE.SiteRecruit.Broker.config.domainMatch,'i');
		if (r.test(_val)) {
			_val = RegExp.$1 + RegExp.$2;
			var c = _name + '=' + _val + '; path=/' + '; domain=' + COMSCORE.SiteRecruit.Broker.config.cookie.domain;
			document.cookie = c; 
		}
	}else if(COMSCORE.isDDInProgress()){	
 		if(_name == "captlinks"){
 			if(/^http(s)?\:/i.test(_val)){
				var _reg = new RegExp("http(s)?://"+document.domain+"/", "i");
 				var _val = _val.replace(_reg, '');
 			}
 			if(_val && _val.length > 2){
				c_vals = readCookie("captlinks");
				if(c_vals){
   				if(c_vals.indexOf(_val) == -1){
   					var str = c_vals +"," + _val;
   					if(str.length <= 1440){
   						_val = str;
   					}else{ _val=false; }
   				}else{ _val = false; }
  			}
 			}
 		}
  	if(_val){
  		var c = _name+'=' + _val + '; path=/' + '; domain=' + COMSCORE.SiteRecruit.Broker.config.cookie.domain;
    	document.cookie = c;
    }
	}
}
// END 5.1.3
var gIdelay = 0;
if (COMSCORE.SiteRecruit.Utils.UserPersistence.getCookieValue("graceIncr") == 1) {
	gIdelay = 5000;
}
setTimeout(function(){_set_SessionCookie("graceIncr", 0)},gIdelay);
//_set_SessionCookie("graceIncr", 0);


//START 5.1.3 CDDS-captLink-graceIncr handlers
function SRappendEventListener(srElement, _name, _val){
	if(srElement.addEventListener){
			srElement.addEventListener('click',function(event){	_set_SessionCookie(_name, _val); },false);
	}else{
			srElement.attachEvent('onclick',function(){	_set_SessionCookie(_name, _val); });
	}
}

function checkLink(){
 var allLinks = document.getElementsByTagName("a");
 for (var i = 0, n = allLinks.length; i < n; i++){
	var r = new RegExp(COMSCORE.SiteRecruit.Broker.config.cddsDomains,'i');
	var _clickURL = allLinks[i].href;

	if(_clickURL && _clickURL != '' && !(/javascript\:void(0)/i.test(_clickURL)) ){

		if (r.test(_clickURL)) {
			SRappendEventListener(allLinks[i], COMSCORE.SiteRecruit.Broker.config.domainSwitch, _clickURL);
		}
	
 		if(/[\w\.]+\/(en-us)\/((default\.aspx|$)|download|business)/i.test(document.location.toString())){
			if(/microsoftstore|store\.microsoft|clk\.atdmt\.com\/MRT\/go\/419363751\/direct|DisplayThreePgCheckoutAddressPaymentInfoPage|msacademicverify|login|(office|office\.microsoft|live|skype|windowsphone|xbox|onedrive)\.com/i.test(_clickURL)){
				SRappendEventListener(allLinks[i], "graceIncr", _clickURL);
				SRappendEventListener(allLinks[i], "captlinks","microsoftstore.com");	
			}
		}else if(/[\w\.]+\/(en-(gb|us)|fr-fr)\/(tablet|phone|laptop|premiumlaptop)/i.test(document.location.toString())){
			if(/CheckOfferEligibility|login\.live|msacademicverify|(o15\.officeredir|office)\.microsoft\.com|login|LiveLogin/i.test(_clickURL)){
				SRappendEventListener(allLinks[i], "graceIncr", _clickURL);
			}
			if(/phone/i.test(allLinks[i].innerHTML)){ _clickURL= _clickURL.replace(/q=(tablet|premiumlaptop|laptop)/i, "q=phone");}
			else if(/tablet/i.test(allLinks[i].innerHTML)){ _clickURL= _clickURL.replace(/q=(phone|premiumlaptop|laptop)/i, "q=tablet");}
			else if(/premiumlaptop/i.test(allLinks[i].innerHTML)){ _clickURL= _clickURL.replace(/q=(phone|laptop|tablet)/i, "q=premiumlaptop");}
			else if(/convertiblelaptops/i.test(allLinks[i].innerHTML)){ _clickURL= _clickURL.replace(/q=(phone|laptop|tablet)/i, "q=convertiblelaptops");}
			else if(/laptop/i.test(allLinks[i].innerHTML)){ _clickURL= _clickURL.replace(/q=(phone|premiumlaptop|tablet)/i, "q=laptop");}
			SRappendEventListener(allLinks[i], "captlinks",_clickURL);	
		}		
	}
	
  if(/[\w\.]+\/(en-(gb|us)|fr-fr)\/(tablet|phone|laptop|premiumlaptop)/i.test(document.location.toString())){	
		//if(/Lumia (930|735|830|phone)/i.test(allLinks[i].innerHTML)){ 
		if(/(Lumia|lumia)/i.test(allLinks[i].innerHTML)){ 
			_clickURL= "q=img_phone"; 
			SRappendEventListener(allLinks[i], "captlinks",_clickURL);
		}else	if(/Lenovo Yoga 3 Pro/i.test(allLinks[i].innerHTML)){ 
			_clickURL= "q=img_premiumLaptop"; 
			SRappendEventListener(allLinks[i], "captlinks",_clickURL);
		}else if(/HP Stream/i.test(allLinks[i].innerHTML)){  
			_clickURL= "q=img_laptop"; 
			SRappendEventListener(allLinks[i], "captlinks",_clickURL);
		}else if(/Surface Pro 3/i.test(allLinks[i].innerHTML)){  
			_clickURL= "q=img_tablet"; 
			SRappendEventListener(allLinks[i], "captlinks",_clickURL);
		}
	}
	
	if(/[\w\.]+\/en-us\/windowsapps/i.test(document.location.toString())){	
			SRappendEventListener(allLinks[i], "captlinks",_clickURL);
		}
	
 }
}

setTimeout("checkLink();", 3000);

if(/[\w\.]+\/(en-(gb|us))\/(tablet|phone|laptop|premiumlaptop)/i.test(document.location.toString())){
	if(document.getElementById("tab1")){
		var srBtn = document.getElementById("tab1");
		SRappendEventListener(srBtn,"captlinks","q=tablet");
	}if(document.getElementById("tab2")){
		var srBtn = document.getElementById("tab2");
		SRappendEventListener(srBtn,"captlinks","q=phone");
	}
}
//END 5.1.3 CDDS-captLink-graceIncr handlers

//START DLC
function checkWTOptimize(){
 try{	
	if(WTOptimize.custom.comScore && WTOptimize.custom.comScore!= null){
		var wtExpId=WTOptimize.custom.comScore;
		if(!(/(1020395\|1020396)|(1020397\|1020398)/i.test(wtExpId))){
			COMSCORE.SiteRecruit._halt = true;
		}else{
			var c = 'wtExpId=' + wtExpId + '; path=/' + '; domain=' + COMSCORE.SiteRecruit.Broker.config.cookie.domain;
			document.cookie = c;
		}
	}else{	COMSCORE.SiteRecruit._halt = true; }
 }catch(err){
		COMSCORE.SiteRecruit._halt = true;
 }
}

if(/www\.microsoft\.com\/en-us\/download\/details\.aspx\?id=3/i.test(window.location.toString())){
	if(COMSCORE.SiteRecruit.Broker.config.delay < 4000){ COMSCORE.SiteRecruit.Broker.config.delay=4000;	}	
	window.setTimeout("checkWTOptimize();", 3000);
}
//END DLC

// START 5.1.3
	function crossDomainCheck() {
		if (intervalMax > 0) {
			intervalMax --;
			
			var cookieName = COMSCORE.SiteRecruit.Broker.config.cddsInProgress;
			
			if (COMSCORE.SiteRecruit.Utils.UserPersistence.getCookieValue(cookieName) != false ) {
				COMSCORE.SiteRecruit.DDKeepAlive.setDDTrackerCookie();
				COMSCORE.SiteRecruit._halt = true;
				clearCrossDomainCheck();
			}
		}
		else {
			clearCrossDomainCheck();
		}
	}

	function clearCrossDomainCheck() {
		window.clearInterval(crossDomainInterval);
	}

	var intervalMax = 10;
	
	var crossDomainInterval = window.setInterval('crossDomainCheck()', '1000');
//END CROSS_DOMAIN DEPARTURE FUNCTIONALITY

//CUSTOM - ADD 5 SECOND DELAY ON CALLING BROKER.RUN()
if (COMSCORE.SiteRecruit.Broker.delayConfig == true)  {
	COMSCORE.SiteRecruit.Broker.config.delay = 5000;
}
//CUSTOM - ADD 20 SECOND DELAY ON CALLING BROKER.RUN() FOR SMB SITES
if(/www\.microsoft\.com\/((en-(ca|in|us)|fr-ca|fr-fr|pt-br|ru-ru|zh-cn)\/business|(en-gb|ja-jp|de-de)\/smb)/i.test(window.location.toString())){
	COMSCORE.SiteRecruit.Broker.config.delay = 20000;
}
window.setTimeout('COMSCORE.SiteRecruit.Broker.run()', COMSCORE.SiteRecruit.Broker.config.delay);
// END 5.1.3