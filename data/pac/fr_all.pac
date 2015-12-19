function base64decode(str) {
    var c1, c2, c3, c4;
    var i, len, out;
    var base64DecodeChars = new Array(
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1);

    len = str.length;
    i = 0;
    out = "";
    while (i < len) {
        do {
            c1 = base64DecodeChars[str.charCodeAt(i++) & 0xff];
        } while (i < len && c1 == -1);
        if (c1 == -1)
            break;

        do {
            c2 = base64DecodeChars[str.charCodeAt(i++) & 0xff];
        } while (i < len && c2 == -1);
        if (c2 == -1)
            break;

        out += String.fromCharCode((c1 << 2) | ((c2 & 0x30) >> 4));

        do {
            c3 = str.charCodeAt(i++) & 0xff;
            if (c3 == 61)
                return out;
            c3 = base64DecodeChars[c3];
        } while (i < len && c3 == -1);
        if (c3 == -1)
            break;

        out += String.fromCharCode(((c2 & 0XF) << 4) | ((c3 & 0x3C) >> 2));

        do {
            c4 = str.charCodeAt(i++) & 0xff;
            if (c4 == 61)
                return out;
            c4 = base64DecodeChars[c4];
        } while (i < len && c4 == -1);
        if (c4 == -1)
            break;
        out += String.fromCharCode(((c3 & 0x03) << 6) | c4);
    }
    return out;
}

function suffix(s1, s2) {
    return s1.indexOf(s2, s1.length - s2.length) !== -1;
}

function isHTTPS(s1) {
    return s1.indexOf('https://', 0) !== -1;
}


function check_ipv4(host) {
    var re_ipv4 = /^\d+\.\d+\.\d+\.\d+$/g;
    if (re_ipv4.test(host)) {
        return true;
    }else{
        return false;
    }
}

function loopc(List, host, Rex) {
    for (var i in List) {
        if (suffix(host,List[i])) {
            return Rex;
        }
    }
    return false;
}

function loopn(List, ip, Rex) {
    for (var i in List) {
        if (isInNet(ip, List[i][0], List[i][1])) {
            return Rex;
        }
    }
    return false;
}

function FindProxyForURL(url, host){
        var L_LAN = [['10.0.0.0', '255.0.0.0'], ['172.16.0.0', '255.240.0.0'], ['192.168.0.0', '255.255.0.0'], ['127.0.0.1', '255.255.255.255']];

    var D = 'DIRECT';
    //ServerList
    if(isHTTPS(url)===false){
        var P = 'HTTPS onenet-fr.vnet.link:211;HTTPS onenet-fr.vnet.link:221;HTTPS onenet-fr.vnet.link:231;PROXY onenet-fr.vnet.link:210;PROXY onenet-fr.vnet.link:220;PROXY onenet-fr.vnet.link:230;';
    }else{
        var P = 'HTTPS onenet-fr.vnet.link:211;HTTPS onenet-fr.vnet.link:221;HTTPS onenet-fr.vnet.link:231;PROXY onenet-fr.vnet.link:210;PROXY onenet-fr.vnet.link:220;PROXY onenet-fr.vnet.link:230;';
    }
    
        
        
    //Preload-DirectGo
    if(suffix(host,'vnet.link')||suffix(host,'getpac.tk')){
        return D;
    }
    
    //Preload-DMM-JP
    if(suffix(host,'dmm.com')||suffix(host,'openx.net')||suffix(host,'jp')){
        return 'HTTPS node-jp.vnet.link:111;PROXY node-jp.vnet.link:101;';
    }
    
        //Preload-Out
    var L_service_out = eval(base64decode('WyJ5b3VrdS5jb20iLCAidHVkb3UuY29tIiwgInNjb3JlY2FyZHJlc2VhcmNoLmNvbSAiLCAiYWRtYXN0ZXIuY29tLmNuIiwgImlyczAxLmNvbSIsICJhbGltYW1hLmNuIiwgInRhbnguY29tIiwgInphbXBkc3AuY29tIiwgIm1tc3RhdC5jb20iLCAiYWxpY2RuLmNvbSIsICJtaWFvemhlbi5jb20iLCAieWtpbWcuY29tIiwgImd0YWdzLm5ldCIsICJjci1uaWVsc2VuLmNvbSIsICJ0ZGltZy5jb20iLCAidGFvYmFvY2RuLmNvbSIsICJtZWRpYXYuY29tIiwgInFpeWkuY29tIiwgInAweS5jbiIsICJxbG9nby5jbiIsICJzaW5haW1nLmNuIiwgImlwaW55b3UuY29tIiwgImd0aW1nLmNuIiwgIjM2MGJ1eWltZy5jb20iLCAidGVuY2VudG1pbmQuY29tIiwgImd0aW1nLmNvbSIsICIzLmNuIiwgInNvaHUuY29tIiwgImlyczAxLm5ldCIsICJpdGMuY24iLCAid3JhdGluZy5jb20iLCAic29nb3UuY29tIiwgIm9wdGFpbS5jb20iLCAiYmFpZHVzdGF0aWMuY29tIiwgImJhaWR1LmNvbSIsICJwYWlwYWlpbWcuY29tIiwgIm1tY2RuLmNuIiwgIm1sdDAxLmNvbSIsICJhY3M4Ni5jb20iLCAieHVubGVpLmNvbSIsICJrYW5rYW4uY29tIiwgInNhbmRhaS5uZXQiLCAia2FuaW1nLmNvbSIsICJyZXZzY2kubmV0IiwgInNjb3JlY2FyZHJlc2VhcmNoLmNvbSIsICJiaWxpYmlsaS5jb20iLCAiYWNndmlkZW8uY29tIiwgImhkc2xiLmNvbSIsICJmdW5zaGlvbi5jb20iLCAiZnVuc2hpb24ubmV0IiwgImJhaWR1c3RhaWMuY29tIiwgImRvdWJsZWNsaWNrLm5ldCIsICJ6aGl6aXl1bi5jb20iLCAiNnJvb21zLmNvbSIsICI2LmNuIiwgImxldHYuY29tIiwgImxldHZjZG4uY29tIiwgImFkbWFzdGVyLmNvbSIsICJsZXR2LmNuIiwgIm1tMTExLm5ldCIsICJhY2Z1bi50diIsICJsZXR2Y2xvdWQuY29tIiwgImlzdHJlYW1zY2hlLmNvbSIsInRvdWRvdXVpLmNvbSJd'));
    var L2x_out = loopc(L_service_out,host,P);
    if(L2x_out!==false){return L2x_out;}   
        
        
    //Default
    return P;}
