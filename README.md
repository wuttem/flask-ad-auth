# flask-ad-auth
Flask Azure AD Authorization Extension (based on flask-login)

This will use the login with Microsoft AZure AD functionality to authorize
users for you flask application. You can Check if an user has a azureAD
user in your organisation or if he belongs to a specific group.

## Register an Azure AD App ##
Next step is registering an app that has read permissions to the Azure AD. You'll need to clientid and clientsecret of this app in order to run this sample against your Azure AD. Follow below steps to register an Azure app:
- Sign in to the Azure management portal
- Click on Active Directory in the left hand nav
- Click the directory tenant where you wish to register the sample application
- Click the Applications tab
- In the drawer, click Add
- Click "Add an application my organization is developing"
- Enter a friendly name for the application, for example "Read Azure AD from SharePoint apps", select "Web Application and/or Web API", and click next
8. For the Sign-on URL, enter a value (this is not used for the console app, so is only needed for this initial configuration): "http://localhost"
- For the App ID URI, enter "http://localhost". Click the checkmark to complete the initial configuration
- While still in the Azure portal, click the Configure tab of your application
- Find the Client ID value and copy it aside, you will need this later when configuring your application
- Under the Keys section, select either a 1year or 2year key - the keyValue will be displayed after you save the configuration at the end - it will be displayed, and you should save this to a secure location. **Note, that the key value is only displayed once, and you will not be able to retrieve it later**
- Configure Permissions - under the "Permissions to other applications" section, you will configure permissions to access the Graph
- The following Permissions are needed: Group.Read.All, User.Read, User.Read.All
- Select the Save button at the bottom of the screen - **upon successful configuration, your Key value should now be displayed - please copy and store this value in a secure location**

## Configuration
You need to set the following Flask Config Variables:
- AD_SQLITE_DB = "my_user_db.db3" 
- AD_APP_ID = "FROM ABOVE"
- AD_APP_KEY = "FROM ABOVE"
- AD_REDIRECT_URI = "http://localhost:5000/connect/get_token" # for testing on localhost

# Usage
```
# In you App Init
from flask import Flask
from flask_ad_auth import ADAuth
app = Flask()
ad_auth = ADAuth()
ad_auth.init_app(app)

# In you Views:
from flask_ad_auth import login_required, current_user, ad_group_required, logout_user

@app.route('/protected')
@login_required
def hello_world1():
    return "Logged in as {}".format(current_user.email)

@app.route('/group_protected')
@ad_group_required("sdadsad-6a93-d3432-a4be-f1cbsdsaa0d4")
def hello_world2():
    return "Logged in as {}".format(current_user.email)

@app.route('/logout')
@ad_group_required("sdadsad-6a93-d3432-a4be-f1cbsdsaa0d4")
def hello_world3():
    logout_user()
    return "Logged out"
```

# Build for PIP

```
python2 setup.py sdist bdist_wheel
python3 setup.py sdist bdist_wheel
twine upload dist/*
```

# Fixes

### Version 0.3 ###

* Fixed SQLite Storage (THX @mowoe)
* Added SQlite Database Test
