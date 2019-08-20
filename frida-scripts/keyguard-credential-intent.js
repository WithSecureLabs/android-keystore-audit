/*
	KeyGuard script which can send a 'createConfirmDeviceCredentialIntent' for invoking a device unlock screen
	Can be used to manually unlock keys which do not have a setUserAuthenticationValidityDurationSeconds set to -1
*/

console.log("Keyguard Script Loaded");
var activitiesList = [];

Java.perform(function () {
    	var activityCls = Java.use("android.app.Activity");
    	activityCls['onCreate'].overload('android.os.Bundle').implementation = function(a1) {
    	activitiesList.push(this);
    	console.log("Acitivity: "+ this);
        return this.onCreate(a1);
    }   
	
});

function showKeyguard()
{
	Java.perform(function () {
		var ActivityThread = Java.use("android.app.ActivityThread");
		var application = ActivityThread.currentApplication().getApplicationContext();
		var REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;
		var KEYGUARD_SERVICE = "keyguard";
		var mKeyguardManagerCls = Java.use("android.app.KeyguardManager");
		var mKeyguardManager = application.getSystemService(KEYGUARD_SERVICE)
		var intent = mKeyguardManagerCls['createConfirmDeviceCredentialIntent'].call(mKeyguardManager,null, null);
		console.log("HERE " + activitiesList[0]);
		activitiesList[0].startActivityForResult(null,intent,REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS,null);
	});
}

/*
* List Activity instances collected in activitiesList   
*/
function ListActivities()
{
    Java.perform(function () {
        for(i=0; i < activitiesList.length; i++)
        {
            console.log( "["+i+"] "+activitiesList[i]);
        } 
    });
    return "[done]";
}

function back(idx)
{
	Java.perform(function () {
		console.log("HERE " + activitiesList[idx]);

			var Runnable = Java.use('java.lang.Runnable');
        	var Runner = Java.registerClass({
                name: 'com.MWR.Runner',
                implements: [Runnable],
                methods: {
                    run: function () 
                        {
                        	activityCls = Java.use("android.app.Activity");
                        	activityCls['onBackPressed'].call(activitiesList[idx]);
							//activitiesList[idx].this$0.value.onBackPressed();
                        }
                }
            });

            var Handler = Java.use('android.os.Handler');
            var Looper = Java.use('android.os.Looper'); 
            var loop = Looper.getMainLooper();
            var handler = Handler.$new(loop);
            handler.post(Runner.$new());		
	});
}
