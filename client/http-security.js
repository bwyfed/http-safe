/**
 * @author Bianwangyang
 * @name http-safe 1.0.0
 * @created : 2017-08-15
 * @description 使用Javascript实现前端防御http劫持及防御XSS攻击，并且对可疑攻击进行上报
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 1、使用方法：调用 httphijack.init({
        whiteList: ['a.com','b.com'],   //白名单入口
        reportUrl: "http://report.url.com",
        rules: {
            "staticScript": false,
            "dynamicScript": function(){
                console.log("dynamicScript callback");
            },
            "inlineEvent": function(){
                console.log("inlineEvent callback");
            },
            "lockCallAndApply":function () {
                console.log("lockCallAndApply callback");
            },
            "iframe": function(){
                console.log("iframe callback");
            },
            "iframeSrc": false
        }
})
 3、防范范围：
 1）所有内联事件执行的代码
 2）href 属性 javascript: 内嵌的代码
 3）静态脚本文件内容
 4）动态添加的脚本文件内容
 5）document-write添加的内容
 6）iframe嵌套
 *
 */
'use strict';
(function(root) {

    var httphijack = function() {},
        inlineEventMap = {}, //内联事件扫描记录
        inlineEventId = 0, //内联事件扫描ID
        scanInlineElement = true, //是否需要扫描内联事件
        whitelistUrl,   //白名单列表的请求URL  字符串 如'http://localhost:3000/api/whitelist'
        reportUrl = 'http://localhost:3000/api/report',
        whiteList;  //安全域 白名单  数组

    // 安全域，白名单
    var safeList = [
        /([a-zA-Z|a-zA-Z\d])+(\.)+(yy|duowan|yystatic|baidu|hiido|qq|baidu|gclick|minisplat|baidustatic|huanjuyun|sina|1931)+(\.)+[A-Za-z]{2,14}/i, //*.yy.com
        /((https|http):\/\/)+([a-zA-Z|a-zA-Z\d])+(\.)+(yy|duowan|yystatic|baidu|hiido|qq|baidu|gclick|minisplat|baidustatic|huanjuyun|sina|1931)+(\.)+[A-Za-z]{2,14}/i, //http开头
        /([a-zA-Z|a-zA-Z\d])+(\.)+(yy|duowan|yystatic|baidu|hiido|qq|baidu|gclick|minisplat|baidustatic|huanjuyun|sina|1931)+(:[0-9]{1,4})+(\.)+[A-Za-z]{2,14}/i, //帶端口的請求
        /[a-zA-Z0-9]\:\/\/[a-zA-Z0-9_/]*/i //手机相关
    ];


    // 危险域，黑名单
    // var dangerList = [];

    // 建立关键词黑名单
    var keywordBlackList = [
        'xss',
        'BAIDU_SSP__wrapper',
        'BAIDU_DSPUI_FLOWBAR'
    ];

    // 过滤class关键词
    var filterClassName = [
        'BAIDU_DUP_wrapper', //百度推广
        'BAIDU_DSPUI_FLOWBAR'
    ];

    // 过滤name关键词
    var filterProName = [
        'text',
        '#text',
        'IFRAME',
        'SCRIPT',
        'IMG'
    ];

    // 过滤id关键词
    var filterNodeId = [
        '1qa2ws'
    ];

    var inlineEventList = [
        'alert',
        'location'
    ];
    // reset console
    if (!console) {
        root.console = {
            log: function() {
                return true;
            }
        };
    }

    /**
     * 统计上报函数
     * @param  {[type]} url 拦截脚本地址
     * @param  {[type]} className 拦截插入元素className
     * @param  {[type]} eName 内联事件名称
     * @param  {[type]} fUrl ifrmae乔套url
     */
    function hiidoStat(url, className, eName, fUrl) {
        var hiidoParam = {
            'eventid': 10010793,
            'bak1': url,
            'bak2': className,
            'bak3': eName,
            'parm1': fUrl
        };
        h5Report(url, className, eName, fUrl);
        root.on_security_interdiction && root.on_security_interdiction.call(root, hiidoParam);
    }

    /**
     * h5性能检测统计
     * @param  {[type]} url 拦截脚本地址
     * @param  {[type]} className 拦截插入元素className
     * @param  {[type]} eName 内联事件名称
     * @param  {[type]} iframeUrl ifrmae乔套url
     */
    function h5Report(url, className, eName, iframeUrl) {
        var databody = {},
            queryStr = '?';

        databody.url = url ? url : '';
        databody.classname = className ? className : '';
        databody.name = eName ? eName : '';
        databody.iframeurl = iframeUrl ? iframeUrl : '';
        databody.pathname = root.location.pathname;
        databody.hostname = root.location.hostname;
        databody.ua = navigator.userAgent;

        for (var n in databody) {
            if (databody[n] !== '') {
                queryStr += n + '=' + databody[n] + '&';
            }
        }
        (new Image).src = reportUrl + queryStr;
    }

    function reportStat(params){
        var databody = {};

        databody.url = params.url ? params.url : ''; //拦截处理的原始url
        databody.classname = params.className ? params.className : ''; //拦截插入元素className
        databody.eventName = params.eventName ? params.eventName : ''; //eName
        databody.iframeUrl = params.iframeUrl ? params.iframeUrl : ''; //页面加入的iframe的URL
        databody.topPageUrl = params.topPageUrl?params.topPageUrl:''; //页面被某个iframe嵌入，top的URL
        // databody.pathname = root.location.pathname;
        // databody.hostname = root.location.hostname;
        databody.ua = navigator.userAgent;  //用户浏览器信息

        var request = new XMLHttpRequest();
        request.open("POST",reportUrl);
        request.setRequestHeader("Content-Type","application/json");
        request.send(JSON.stringify(databody));
    }
    /**
     * 过滤指定关键字
     * @param  {[Array]} list 过滤词库
     * @param  {[String]} value    [需要验证的字符串]
     * @return {[Boolean]}         [false -- 验证不通过，true -- 验证通过]
     */
    function filter(list, value) {
        //如果要验证的子串为空，或者含有脚本文件名本身
        if(!value||value.indexOf('http-security.js')!==-1) {
            return true;
        }
        var length = list.length,
            i = 0;
        for (; i < length; i++) {
            // 建立黑名单正则
            var reg = new RegExp(list[i]);

            // 存在黑名单中，拦截
            if (reg.test(value.replace('https://', '').replace('http://', ''))) {
                return true;
            }
        }
        return false;
    }

    //内联事件和内联脚本劫持
    function inlineEventScriptFilter(callback) {
        var allNodes = document.all,ele;
        for(var i=0; i<allNodes.length; i++) {
            ele = allNodes[i];
            scanHTMLElement(ele);
        }
    }
    // 过滤内联事件和内联脚本 普通元素过滤on开头的事件，使用inlineEventList过滤
    // 另有，a标签过滤href="javascript:..."后面的黑名单关键词keywordBlackList
    // iframe标签过滤src="javascript:..."后面的内联事件黑名单inlineEventList
    function scanHTMLElement(node) {
        var attrs = node.attributes,attr,attrName,attrValue;
        // console.log(node.nodeName);
        function filterValue(tagName,attrValue) {
            if(attrValue.length===2) {
                attrValue = attrValue[1];
            } else {
                attrValue = '';
            }
            if(tagName==='A') {
                //a标签的内联脚本，过滤关键词黑名单keywordBlackList
                if (filter(keywordBlackList, attrValue)) {
                    // 注销代码
                    node.href = 'javascript:void(0)';
                    console.log('拦截A的内联可疑脚本:' + attrValue);
                }
            } else if(tagName==='IFRAME') {
                if (filter(inlineEventList, attrValue)) {
                    // 注销代码
                    node.src = 'javascript:void(0)';
                    console.log('拦截IFRAME可疑事件:' + attrValue);
                }
            }

        }
        for(var i in attrs) {
            if(attrs.hasOwnProperty(i)) {
                attr = attrs[i];
                attrName = attr["name"];
                attrValue = attr["value"];
                //扫描包括 a iframe img video div 等所有可以写内联事件的元素
                if (attrName.indexOf('on')===0) {
                    if (filter(inlineEventList, attrValue)) {//这里还可以过滤keywordBlackList
                        // 注销事件
                        node[attrName] = null;
                        console.log('拦截可疑内联事件:' + attrValue);
                    }
                }

                // 扫描 <a href="javascript:"> 的脚本 <iframe src="javascript:alert(1)">的脚本
                if (node.tagName === 'A'||node.tagName ==='IFRAME') {
                    var r = new RegExp('javascript:(.*)');
                    if(node.tagName === 'A'&&attrName==='href'&&node.protocol === 'javascript:') {
                        //A标签
                        attrValue = node.href.match(r);
                        filterValue(node.tagName, attrValue);
                    } else if(node.tagName ==='IFRAME'&&attrName==='src'&&node.src.indexOf('javascript:')!==-1) {
                        //iframe标签
                        attrValue = node.src.match(r);
                        filterValue(node.tagName, attrValue);
                    }
                }
            }
        }
    }
    // 内联事件劫持
    function inlineEventFilter(callback) {
        var i = 0,
            obj = null;

        //遍历文档根节点上的所有内联事件（以on开头）
        for (obj in document) {
            if (/^on./.test(obj)) {
                interceptionInlineEvent(obj, i++);
            }
        }
        if(callback&&typeof callback==='function') {
            callback();
        }
    }

    /**
     * 内联事件拦截
     * @param  {[String]} eventName [内联事件名]
     * @param  {[Number]} eventID   [内联事件id]
     * @return {[type]}             [description]
     */
    function interceptionInlineEvent(eventName, eventID) {
        var isClick = (eventName === 'onclick');

        document.addEventListener(eventName.substr(2), function(e) {
            scanElement(e.target, isClick, eventName, eventID);
        }, true);
    }

    /**
     * 扫描元素是否存在内联事件
     * @param  {[DOM]} elem [DOM元素]
     * @param  {[Boolean]} isClick [是否是内联点击事件]
     * @param  {[String]} eventName [内联 on* 事件名]
     * @param  {[Number]} eventID [给每个内联 on* 事件一个id]
     */
    function scanElement(elem, isClick, eventName, eventID) {
        var flag = elem.isScan,
            code = '', // 扫描内联代码
            hash = 0;

        // 跳过已扫描的事件
        if (!flag) {
            flag = elem.isScan = ++inlineEventId;
        }

        hash = (flag << 8) | eventID;

        if (hash in inlineEventMap) {
            return;
        }

        inlineEventMap[hash] = true;

        // 非元素节点
        if (elem.nodeType !== Node.ELEMENT_NODE) {
            return;
        }
        //扫描包括 a iframe img video div 等所有可以写内联事件的元素
        if (elem[eventName]) {
            code = elem.getAttribute(eventName);
            if (code && filter(inlineEventList, code)) {
                // 注销事件
                elem[eventName] = null;
                hiidoStat('', '', code, '');
                // console.log('拦截可疑内联事件:' + code);
            }
        }

        // 扫描 <a href="javascript:"> 的脚本
        if (isClick && elem.tagName === 'A' && elem.protocol === 'javascript:') {
            code = elem.href.substr(11);
            if (filter(inlineEventList, code)) {
                // 注销代码
                elem.href = 'javascript:void(0)';
                hiidoStat('', '', code, '');
                // console.log('拦截可疑事件:' + code);
            }
        }

        // 递归扫描上级元素
        scanElement(elem.parentNode);
    }

    /**
     * 扫描页面中已经存在的script脚本，脚本已执行
     * 没法拦截，只能上报
     */
    function scanStaticScript() {
        var staticScripts = document.getElementsByTagName("script"),script;
        console.log('scan static script=====start');
        for(var i=0; i < staticScripts.length; i++) {
            script = staticScripts[i];
            console.log(script.src);
            if (!filter(whiteList, script.src)) {
                script.parentNode && script.parentNode.removeChild(script);
                console.log('发现可疑静态脚本:', script.src);
                // hiidoStat(node.src, 'insertScriptTag', '', '');
            }
        }
        console.log('scan static script=====end');
    }

    /**
     * 监听DOM树的变化，对非法脚本进行拦截
     */
    function monitorScripts() {
        var MutationObserver = root.MutationObserver || root.WebKitMutationObserver || root.MozMutationObserver;
        // 该构造函数用来实例化一个新的 Mutation 观察者对象 Mutation 观察者对象能监听在某个范围内的 DOM 树变化
        if (!MutationObserver) return;
        var observer = new MutationObserver(function(mutations) {
            console.log('MutationObserver event***********begin');
            mutations.forEach(function(mutation) {
                var nodes = mutation.addedNodes;
                // 逐个遍历
                for (var i = 0; i < nodes.length; i++) {
                    var node = nodes[i];
                    console.log(node.tagName);
                    // 扫描 script 与 iframe
                    if (node.tagName === 'SCRIPT' || node.tagName === 'IFRAME') {
                        // 拦截到可疑iframe
                        if (node.tagName === 'IFRAME' && node.src && !filter(whiteList, node.src)) {
                            node.parentNode && node.parentNode.removeChild(node);
                            // hiidoStat('', 'insertIFRMAETag', '', node.src);
                            console.log('拦截到可疑iframe', node.src);
                        } else if (node.src) {
                            // 只放行白名单
                            if (!filter(whiteList, node.src)) {
                                node.parentNode && node.parentNode.removeChild(node);
                                // hiidoStat(node.src, 'insertScriptTag', '', '');
                                console.log('拦截可疑静态脚本:', node.src);
                            }
                        }
                    }
                }
            });
            console.log('MutationObserver event***********end');
        });

        // 传入目标节点和观察选项
        // 如果 target 为 document 或者 document.documentElement
        // 则当前文档中所有的节点添加与删除操作都会被观察到d
        observer.observe(document, {
            subtree: true,
            childList: true
        });
    }
    /**
     * 主动防御 MutationEvent
     * 使用 MutationObserver 进行静态插入脚本的拦截
     * @return {[type]} [description]
     */
    function interceptionStaticScript(callback) {
        //监控当前页面已存在的静态脚本
        scanStaticScript();
        monitorScripts();
    }

    /**
     * 使用 DOMNodeInserted  进行动态脚本拦截监
     * 此处无法拦截，只能监测
     * @return {[type]} [description]
     */
    function interceptionDynamicScript(callback) {
        document.addEventListener('DOMNodeInserted', function(e) {
            console.log(e.type);
            var node = e.target;

            // if (!filter(whiteList, node.src) || filter(filterClassName, node.className) || filter(filterProName, node.name) || filter(filterNodeId, node.id)) {
            if (!filter(whiteList, node.src)) {
                // node.parentNode.removeChild(node);
                // hiidoStat(node.src ? node.src : '', node.className ? node.className : '', node.name ? node.name : '', '');
                console.log('拦截可以创建节点：'+ node.nodeName + ',id为：'+(node.id?node.id:''));
            }
            if(callback&&typeof callback==='function') {
                callback();
            }
        }, true);
    }

    /**
     * 重写单个 root 窗口的 document.write 属性
     * @param  {[BOM]} root [浏览器window对象]
     * @return {[type]}       [description]
     */
    function resetDocumentWrite(root) {
        var overWrite = root.document.write;

        root.document.write = function(string) {
            if (filter(filterClassName, string) || filter(filterProName, string) || filter(filterNodeId, string)) {
                hiidoStat('', string, '', '');
                // console.log('拦截可疑模块:', string);
                return;
            }
            overWrite.apply(document, arguments);
        };
    }

    /**
     * 重写单个 root 窗口的 setAttribute 属性
     * @param  {[BOM]} root [浏览器window对象]
     * @return {[type]} [description]
     */
    function resetSetAttribute(root) {
        var overWrite = root.Element.prototype.setAttribute;

        root.Element.prototype.setAttribute = function(name, value) {
            if ((this.tagName === 'SCRIPT'||this.tagName === 'IFRAME')&& /^src$/i.test(name)) {
                if (!filter(whiteList, value)) {
                    //hiidoStat(value, '', '', '');
                    // console.log('拦截可疑模块:', value);
                    //如果页面被添加了iframe，就应该将其隐藏
                    if(this.tagName==='IFRAME') {
                        this.style.display = 'none';
                        reportStat({
                            url: window.location.href,  //原始页面的URL
                            eventName: 'add iframe into page',   //事件名称
                            eventId: 10002,         //事件代码
                            iframeUrl: value,       //新加入iframe的URL
                            topPageUrl: window.location.href    //顶级页面的URL
                        });
                    }
                    return;
                }
            }
            overWrite.apply(this, arguments);
        };
    }

    function filterIframes() {
        var iframes = document.getElementsByTagName('iframe'),iframe,src;
        for(var i=0; i < iframes.length; i++) {
            iframe = iframes[i];
            console.log(iframe.src);
            src = iframe.src;
            if(src) {
                if(!filter(whiteList,src)) {
                    //如果不在白名单中，那么拦截并上报
                    iframe.style.display = 'none';
                    reportStat({
                        url: window.location.href,  //原始页面的URL
                        eventName: 'add iframe into page',   //事件名称
                        eventId: 10002,         //事件代码
                        iframeUrl: src,       //新加入iframe的URL
                        topPageUrl: window.location.href    //顶级页面的URL
                    });
                }
            }
        }
    }

    /**
     * 使用 MutationObserver 对生成的 iframe 页面进行监控，
     * 防止调用内部原生 setAttribute 及 document.write
     * @return {[type]} [description]
     */
    function defenseIframe(callback) {
        // 先保护当前页面
        installHook(root);
        if(callback&&typeof callback==='function') {
            callback();
        }
    }

    /**
     * 实现单个 window 窗口的 setAttribute保护
     * @param  {[BOM]} root [浏览器window对象]
     * @return {[type]}       [description]
     */
    function installHook(root) {
        //重写单个window窗口的setAttribute属性
        resetSetAttribute(root);
        filterIframes(root);
        // resetDocumentWrite(root);

        // MutationObserver 的不同兼容性写法
        var MutationObserver = root.MutationObserver || root.WebKitMutationObserver || root.MozMutationObserver;
        if (!MutationObserver) return;
        // 该构造函数用来实例化一个新的Mutation观察者对象
        // Mutation观察者对象能监听在某个范围内的 DOM 树变化
        var observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                //返回被添加的节点，或者为null
                var nodes = mutation.addedNodes;

                for (var i = 0; i < nodes.length; i++) {
                    var node = nodes[i];

                    // 给生成的 iframe 里环境也装上重写的钩子
                    if (node.tagName === 'IFRAME') {
                        node.contentWindow && installHook(node.contentWindow);
                    }
                }
            });
        });

        observer.observe(document, {
            subtree: true,
            childList: true
        });
    }

    /**
     * 使用 Object.defineProperty，锁住call和apply，使之无法被重写
     * @return {[type]} [description]
     */
    function lockCallAndApply(callback) {
        // 锁住 call
        try {
            Object.defineProperty(Function.prototype, 'call', {
                value: Function.prototype.call,
                // 当且仅当仅当该属性的 writable 为 true 时，该属性才能被赋值运算符改变
                writable: false,
                // 当且仅当该属性的 configurable 为 true 时，该属性才能够被改变，也能够被删除
                configurable: false,
                enumerable: true
            });
            // 锁住 apply
            Object.defineProperty(Function.prototype, 'apply', {
                value: Function.prototype.apply,
                writable: false,
                configurable: false,
                enumerable: true
            });
        } catch (e) {
            // console && console.log(e);
        }

        if(callback&&typeof callback==='function') {
            callback();
        }

    }
    /**
     * 操作cookie的方法
     */
    var s__cookie = {
        set: function(key, val) {
            var date = new Date();
            date.setTime(date.getTime() + 60 * 1000); //格式化为cookie识别的时间
            document.cookie = key + '=' + val + ';expires=' + date.toGMTString(); //设置cookie
        },
        get: function(key) {
            var getCookie = document.cookie.replace(/[ ]/g, '');
            var arrCookie = getCookie.split(';');
            var tips;
            for (var i = 0; i < arrCookie.length; i++) {
                var arr = arrCookie[i].split('=');
                if (key == arr[0]) {
                    tips = arr[1];
                    break;
                }
            }
            return tips;
        }
    };
    /**
     * 此页面存在于一个iframe中
     * 重定向iframe url（页面被iframe包裹）
     */
    function redirectionIframeSrc(callback) {
        var flag = 'iframe_hijack_redirected';

        if (self !== top) {
            var parentUrl = document.referrer,
                length = whiteList.length,
                i = 0;

            for (; i < length; i++) {
                // 建立白名单正则
                var reg = new RegExp(whiteList[i], 'i');

                // 存在白名单中，放行
                if (reg.test(parentUrl)) {
                    return;
                }
            }

            //我们的正常页面
            var url = location.href;
            var parts = url.split('#');
            //模拟已经被劫持过了
            if (location.search) {
                parts[0] += '&' + flag + '=3';
            } else {
                parts[0] += '?' + flag + '=3';
            }
            try {
                top.location.href = parts.join('#');
                if (!s__cookie.get('HtpLocTmp')) {
                    // cookie记录这次跳转的时间点
                    s__cookie.set('HtpLocTmp', '1');
                }
                reportStat({
                    url: window.location.href,  //原始页面的URL
                    eventName: 'page is embbed in iframe',   //事件名称
                    eventId: 10001,         //事件代码
                    iframeUrl: '',       //新加入iframe的URL
                    topPageUrl: parentUrl    //顶级页面的URL
                });
                // console.log('页面被嵌入iframe中:', parentUrl);
            } catch (e) {
                reportStat({
                    url: window.location.href,  //原始页面的URL
                    eventName: 'page is embbed in iframe,redirect fail',   //事件名称
                    eventId: 10001,         //事件代码
                    iframeUrl: '',       //新加入iframe的URL
                    topPageUrl: parentUrl    //顶级页面的URL
                });
                // console.log('页面被嵌入iframe中, 重定向失败');
            }
            if(callback&&typeof callback==='function') {
                callback();
            }
        }
    }

    //生成安全域白名单的正则表达式列表
    function generateWhiteListReg(whitelist) {
        var strreg = whitelist.join('|'),
            reg1 = new RegExp("([a-zA-Z|a-zA-Z\\d])+(\\.)+("+strreg+")+(\\.)+[A-Za-z]{2,14}","i"),  // *.yy.com
            reg2 = new RegExp("((https|http):\\/\\/)+([a-zA-Z|a-zA-Z\d])+(\\.)+(" + strreg + ")+(\\.)+[A-Za-z]{2,14}","i"), //http开头
            reg3 = new RegExp("([a-zA-Z|a-zA-Z\\d])+(\.)+(" + strreg + ")+(:[0-9]{1,4})+(\\.)+[A-Za-z]{2,14}","i"), //帶端口的請求
            reg4 = new RegExp("[a-zA-Z0-9]\\:\\/\\/[a-zA-Z0-9_/]*","i"); //手机相关
        return [reg1, reg2, reg3, reg4];
    }
    function __init() {
        function initRules() {
            rulemap["iframeSrc"]&&redirectionIframeSrc(rulemap["iframeSrc"][1]);
            rulemap["iframe"]&&defenseIframe(rulemap["iframe"][1]);
            rulemap["dynamicScript"]&&interceptionDynamicScript(rulemap["dynamicScript"][1]);
            rulemap["inlineEvent"]&&scanInlineElement && inlineEventScriptFilter(rulemap["inlineEvent"][1]);
            rulemap["staticScript"]&&interceptionStaticScript(rulemap["staticScript"][1]);
            rulemap["lockCallAndApply"]&&lockCallAndApply(rulemap["lockCallAndApply"][1]);
        }
        if(whitelistUrl) {
            axios.get(whitelistUrl)
                .then(function(response){
                    console.log(response.data);
                    safeList = generateWhiteListReg(response.data);
                })
        } else if(whiteList) {
            safeList = generateWhiteListReg(whiteList);
        }
        initRules();
    }

    var defaultCallback = function() {
        // console.log('默认的处理规则的回调函数');
        //上报事件

    };
    var rulemap = {
        "staticScript": [interceptionStaticScript,defaultCallback],
        "dynamicScript": [interceptionDynamicScript,defaultCallback],
        "inlineEvent": [inlineEventScriptFilter,defaultCallback],
        "lockCallAndApply": [lockCallAndApply,defaultCallback],
        "iframe": [defenseIframe,defaultCallback],
        "iframeSrc": [redirectionIframeSrc,defaultCallback]
    };
    // 初始化方法
    httphijack.init = function(options) {
        var type = typeof options,rule;
        if(type==='object'&& !(length in options)){
            if(options.rules) {
                for(rule in rulemap) {
                    if(options.rules.hasOwnProperty(rule)&& typeof options.rules[rule]==='function') {
                        //说明不使用默认的回调方法
                        rulemap[rule][1] = options.rules[rule];
                    } else if(!options.rules[rule]) {
                        delete rulemap[rule];
                    }
                }
                //遍历由规则和回调构成的对象
                /*
                for(rule in options.rules) {
                    if(!options.rules[rule]) {
                        //说明不需要这个rule
                        delete rulemap[rule];
                    } else if(typeof options.rules[rule]==='function') {
                        //说明不使用默认的回调方法
                        rulemap[rule][1] = options.rules[rule];
                    }
                }
                */
            }
            if(options.reportUrl) {
                reportUrl = options.reportUrl;
            }
            if(options.whitelistUrl) {
                whitelistUrl = options.whitelistUrl;
            }
            if(options.whiteList&&Array.isArray(options.whiteList)) {
                whiteList = options.whiteList;
            }
        }
        __init();
        console.log(rulemap);
    };


    if (typeof define === 'function' && define.amd) {
        define('httphijack', [], function() {
            return httphijack;
        });
    } else {
        root.httphijack = httphijack;
    }

    // 不支持 IE8-
    if (navigator.appName == 'Microsoft Internet Explorer' && (navigator.appVersion.split(';')[1].replace(/[ ]/g, '') == 'MSIE6.0' || navigator.appVersion.split(';')[1].replace(/[ ]/g, '') == 'MSIE7.0' || navigator.appVersion.split(';')[1].replace(/[ ]/g, '') == 'MSIE8.0')) {
        return;
    } else {
        /*
        if (!(/localhost/i).test(location.host) || (navigator.appName === 'Microsoft Internet Explorer' && (navigator.appVersion.match(/7./i) !== '7.' || navigator.appVersion.match(/8./i) !== '8.'))) {
            httphijack.init();
        }
        */
    }
}(window))