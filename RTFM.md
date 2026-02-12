# RTFM
**Challenge Author:** f0rk3b0mb  
**Category:** Web  
**Files Provided:** `public.zip`  
Solves: `78`
# 1. Challenge Overview
![](<images/Pasted image 20251207202035.png>)

We are given a Flask-based web app inside `public.zip`. The challenge description simply says:

> _“It's up to you to find the flag…”_

No endpoint information, no hint.  
So , as the challenge title suggests --> **RTFM: Read The (Flask) Manual.**

This implies the vulnerability is hidden in the code itself.

# 2. Exploring the Web Interface

The provided link leads to a basic login/register form:

![](<images/Pasted image 20251207202444.png>)

Registering and logging in works—but no admin panel or hint of a flag appears:

![](<images/Pasted image 20251208180522.png>)

No visible attack surface.  

So as the title says: **Read The Manual (the source code).**
# 3. Inspecting the Provided Files

After extracting `public.zip`, the structure looks like this:

![](<images/Pasted image 20251207202234.png>)

This is effectively the **entire backend** of the deployed challenge.  
From this point, the goal is to **read the backend logic and uncover hidden admin functionality**.

The two most important elements:
### ✔ `app.py` --> main backend logic

### ✔ `users` --> SQLite database storing accounts & roles


# 4. Source Code Analysis (RTFM)

The most interesting route is the admin dashboard:

```python
@app.route('/admin/dashboard', methods=['GET'])

def admin_dashboard():

    username = session.get('username')

    if not username:

        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    user = get_user(username)

    if not user:

        return jsonify({'success': False, 'error': 'User not found'}), 404

    if not user['is_admin']:

        return jsonify({'success': False, 'error': 'Access denied: Admin only'}), 403

    return jsonify({

        'success': True,

        'title': 'Admin Dashboard',

        'FLAG': 'flag\{example_flag_for_testing\}',

        'message': 'Admin panel accessed successfully'

    })
```


Aha.  
The **flag lives inside `/admin/dashboard`**, but access is restricted to admin users.

Trying to visit `/admin/dashboard` as a normal user yields:

**403 Access denied: Admin only**

![](<images/Pasted image 20251209173731.png>)

So the question becomes:

> **How do we become an admin?**

The answer appears elsewhere in the code.

# 5. The Vulnerability: Unauthenticated Admin Promotion
Inside `app.py`, we find this route:

```python
@app.route('/addAdmin', methods=['GET'])

def addAdmin():

    username = request.args.get('username')

    if not username:

        return response('Invalid username'), 400

    result = makeUserAdmin(username)

  

    if result:

        return response('User updated!')

    return response('Invalid username'), 400
```


It calls a function `makeUserAdmin` . Lets check it out:

```python
def make_user_admin(username):

    conn = get_db_connection()

    c = conn.cursor()

    c.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (username,))

    conn.commit()

    affected = c.rowcount

    conn.close()

    return affected > 0
```
###  _Critical flaw:_

- No authentication
- No admin check
- No CSRF protection
- No validation

Anyone on the internet can elevate **any username** to admin privileges by calling one GET endpoint:
```
/addAdmin?username=<target>

```

This is a textbook **Broken Access Control** vulnerability.

# 6. Exploitation
### Step 1: Register a normal user

Example username: **shanks**
### Step 2: Promote yourself to admin

Visit:

```
addAdmin?username=shanks
```

Server responds:

`User updated!`

![](<images/Pasted image 20251209174926.png>)

We were promoted to admin

I just appended  the `GET` request by adding `/addAdmin?username=<your username goes here>`
as mentioned in the code the username is an argument to the route.
### Step 3: Access the admin dashboard
Now simply visit:
```
/admin/dashboard
```

![](<images/Pasted image 20251209175613.png>)

We got the flag finally :

```
r00t{749b487afaf662a9a398a325d3129849}
```

# 7.Final Flag 
![](<images/Pasted image 20251209175808.png>)

# 8.Conclusion
RTFM is a clean introduction to code-review web exploitation.  
By inspecting only a few lines of Python, we uncover a full privilege escalation vulnerability that grants access to the admin panel and reveals the flag.

A simple but elegant challenge.

# *Discord : @shankscx*
