# flask-ad-auth
Flask Azure AD Authorization Extension (based on flask-login)

This will use the login with Microsoft AZure AD functionality to authorize
users for you flask application. You can Check if an user has a azureAD
user in your organisation or if he belongs to a specific group.

## Register an Azure AD App ##

*Important*

This it the link to the Microsoft Doc for registering an App: https://learn.microsoft.com/en-us/graph/auth-register-app-v2
If you have problems use this documentation as I will not be able to always keep this doc up to date.

You need to register an app that has read permissions to the Azure AD. You'll need to add clientid and clientsecret of this app in order to run this sample against your Azure AD. Follow below steps to register an Azure app:
- Sign in to the Azure management portal and to the Azure Active Directory Tab: https://aad.portal.azure.com/
- Goto: "App Registrations" and click "New registration".
- Enter a friendly name for the application, for example "Example Azure AD Read App", select "Web" and use `http://localhost:5000/connect/get_token` as a Redirect URI.
- Find the Client ID value and copy it aside, you will need this later when configuring your application.
- While still in the Azure portal, click the "Certificates & secrets" tab of the application you created.
- Create a new "Client Secret" - the keyValue will be displayed after you save the configuration at the end - it will be displayed, and you should save this to a secure location. **Note, that the key value is only displayed once, and you will not be able to retrieve it later**.
- Configure Permissions - under the "Permissions to other applications" section, you will configure permissions to access the Graph.
- The following Permissions are needed to use all features of this library: Group.Read.All, User.Read, User.Read.All.
- Add additional Perimissions that you need here.

**To use this on a server you have to replace the REDIRECT_URL with your domain. You might also want to configure a "Front-channel logout URL" that redirects to your logout page.**

## Configuration
You need to set the following Flask Config Variables:
- AD_SQLITE_DB = "my_user_db.db3" # or use REDIS
- AD_APP_ID = "CLIENT ID FROM ABOVE"
- AD_APP_KEY = "SECRET VALUE FROM ABOVE"
- AD_TENANT_ID = "YOUR AZURE AD TENANT ID"
- AD_REDIRECT_URI = "http://localhost:5000/connect/get_token" # for testing on localhost
- AD_DOMAIN_FOR_GROUPS = "YOUR AZURE AD DOMAIN NAME [example.com]" # Mandatory if you want to use @ad_group_required("<azure_ad_group_uuid>")

# Usage
```
# In you App Init
from flask import Flask
from flask import url_for, redirect, request
from flask_ad_auth import ADAuth

app = Flask(__name__)
app.secret_key = <SOME SECRET KEY>
app.config.update(
    AD_SQLITE_DB = "my_user_db.db3",
    AD_APP_ID = <YOUR CLIENT ID>,
    AD_APP_KEY = <YOUR SECRET>,
    AD_TENANT_ID = <TENANT>
    AD_REDIRECT_URI = "http://localhost:5000/connect/get_token",
    AD_LOGIN_REDIRECT = "/login_form"
)
ad_auth = ADAuth()
ad_auth.init_app(app)

# In you Views:
from flask_ad_auth import login_required, current_user, ad_group_required, logout_user

@app.route('/protected')
@login_required
def protected_view():
    return "Logged in as: {}".format(current_user.email)

@app.route('/group_protected')
@ad_group_required("sdadsad-6a93-d3432-a4be-f1cbsdsaa0d4")
def group_protected_view():
    return "Logged in as: {}".format(current_user.email)

@app.route('/logout')
def logout():
    logout_user()
    return 'Logged out<br/><a href="{}">goto login page</a>'.format(url_for("login_form"))

@app.route('/')
@app.route('/login_form')
def login_form():
    if current_user.is_authenticated:
        return 'logged in as {}<br/><a href="{}">logout</a>'.format(current_user.email, url_for("logout"))
    return 'not logged in<br/><a href="{}">login</a>'.format(ad_auth.sign_in_url)

if __name__ == '__main__':
	app.run( debug=True, host='0.0.0.0', port=5000)
```

# Build for PIP

```
python2 setup.py sdist bdist_wheel
python3 setup.py sdist bdist_wheel
twine upload dist/*
```

# Changes

### Version 1.1.1 ###

* Fixed Readme and added some more information


### Version 1.1.0 ###

* Fixed imports for flask 3.0

### Version 1.0.1 ###

** This release might break compatibility! Make sure you are using the right config values **

* Rewrite using msal: https://github.com/AzureAD/microsoft-authentication-library-for-python
* Using new Auth Flow as recommended by Microsoft
* Removed some old stuff


### Version 0.8.2 ###

* Small changes to doc and example


### Version 0.8 ###

* Fixed Setup for pypi installs

### Version 0.7 ###

* Fixed an edge case in which the refresh token was not accepted anymore

### Version 0.6 ###

* New Config: "AD_AUTH_USER_BASECLASS" sets the base for all Users

### Version 0.5 ###

* Added Group Name Cache
* Group-Access now takes name or id of the group

### Version 0.4 ###

* Reload on Empty Database fixed

### Version 0.3 ###

* Fixed SQLite Storage (THX @mowoe)
* Added SQlite Database Test
