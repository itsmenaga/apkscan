import subprocess
import zipfile

subprocess.call(['java', '-jar', 'apktool_2.1.1.jar', 'd', 'facebook.apk', '-o', 'test'])

subprocess.call(['python', '-m', 'zipfile', '-c', 'test.zip', 'test'])

try:
	root = zipfile.ZipFile("test.zip", "r")
	print "Check For SSL Certificate Pinning:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("getCertificatePinningSSL") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("libliger-native.so") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("proxygen::SSLVerification::verifyWith") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("certPinner") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("okHttpClient") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("CertificatePinner") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("retrofit" or "Retrofit.Builder") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("Picasso" or "Picasso.Builder") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("validatePinning") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("PinningHostnameVerifier") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("Volley.newRequestQueue" or "Volley") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For File References:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("file://") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("getSharedPreferences") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("getExternal") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For Auth Bearers:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("authBearer") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("Bearer") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("authtoken") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("auth") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("Oauthtoken") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For debug and export:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("debug") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("export") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("exported=true") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For SSL Insecure method:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("getInsecure") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("getInsecure" and "SSLCertificateSocketFactory") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("getInsecure" and "SSLSocketFactory") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For Token, Keys and Credentials:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("token") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("key") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("password") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("pwd") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("admin") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("root") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("credential") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For Sim, SMS and Network Records:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("telephony") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("TelephonyManager") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("getSimOperator") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("getSimOperatorName") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("getDeviceId") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("getSimSerialNumber") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("getLastKnownLocation") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("telephony.SmsManager") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("?TextMessage") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For World Readable and Writable Permissions:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("MODE_WORLD_READABLE") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("MODE_WORLD_WRITABLE") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("openFileOutput") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For WebView XSS:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("setJavaScriptEnabled") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("addJavascriptInterface") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For Rooted Device and Su privileges:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("superuser" or "supersu" or "noshufou") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("Superuser.apk") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("isDeviceRooted") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("RootTools.isAccessGiven") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For Sleep Method:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("SystemClock" and "sleep") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For System Command Execution:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("getRuntime") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("Runtime.getRuntime") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For Obfuscated code:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("getObfuscator") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("AESObfuscator") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For Insecure SSL Certificates:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("Trust" and "SSLSocket") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("NonValidatingSSLSocketFactory") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("ALLOW_ALL_HOSTNAME_VERIFIER") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("setDefaultHostnameVerifier") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("NullHostnameVerifier") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For Sql Injection:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("rawQuery") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("execSQL") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("database") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find(".sqlite") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("SQLiteDatabase") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
	print "Check For Castor Library XXE Vulnerability:"
	for name in root.namelist(  ):
		lines = root.open(name).readlines()
		lineno = 0
		for line in lines:
			lineno += 1
			if line.find("castor.sax") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			elif line.find("castor") >= 0:
				print "File Path : ",name+","+"Snippet : ",line+","+"Line Number : ",lineno
			else:
				pass
except:
	pass