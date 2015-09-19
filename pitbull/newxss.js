var casper = require('casper').create({
    logLevel: 'warning',
    verbose: true,
    onAlert: function(msg) {

        Message = msg + '';
        var vulnWarning = Message.replace(/\[object Casper\]/g, "");
        casper.log(vulnWarning);
        vulns.push(vulnWarning);

    },
    XSSAuditingEnabled: false
});

casper.userAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X)');

var fs = require('fs');
var utils = require('utils');
//var data = fs.read('rsnake.txt');
var data = fs.read('noxssrsnake.txt');
var xss = data.toString().split("\n");

var checks = ["sUshI"]

var fullChecks = false
var stringFoundInResponse = false

var payloads = [];
var cookieCli = casper.cli.get("cookie");

var ID = casper.cli.get("ID");
var url = casper.cli.get("url");
var postdata = casper.cli.get("postdata");
var postheader = casper.cli.get("postheader");
var pitserver = casper.cli.get("pitserver");
var url_backup = casper.cli.get(1);

if (!url){
    url = url_backup
}

var string = casper.cli.raw.get("string");
var params = []
var detectedParameters;
var vulns = [];
var count;

var alldata = postdata;

try {
    var uri = url.split('?');
    var queryString = uri[1];
    var uri = uri[0];

} catch (err) {

}

var storedParamValues;

if(casper.cli.has("postdata") != true)
{
    
    var casperXSS = {
        analyze: function() {

            var setParameters = function(setpayloads) {
                for (i = 0; i < params.length; i++) {
                    console.log("Detected the \"" + params[i] + "\" parameter, adding it into scope.");
                }
                setpayloads()
            }

            setParameters(this.setPayloads);
          
        },
        setPayloads: function() {

            for (z = 0; z < params.length; z++) {
                for (x = 0; x < xss.length; x++) {
                        var payloadString = uri + '?' + params[z] + '=' + xss[x]
                        for (y = 0; y < params.length; y++)
                        {
                            if(y != z){
                                payloadString += '&' + storedParamValues[y]
                            }
                        }
                        payloads.push(payloadString);
                }
            }

            casperXSS.scan()

        },
        detectParameters: function(url, analyze) {
            storedParamValues = queryString.split('&')
            detectedParameters = queryString.split('&');

            for (i = 0; i < detectedParameters.length; i++) {
                tempParam = detectedParameters[i].replace(/(=.*)/i, "");

                params.push(tempParam);
            }
            analyze();
        },
        scan: function() {
            //console.log('\nTrying ' + payloads.length + ' payloads on a total of ' + params.length + ' parameter. \nSit back and enjoy the ride.\n');
            // add regex to clean up xss validation msg (\[object Casper\], fuck)
            casper.start(url, function(status) {


            });
            casper.run()
            casper.then(function() {
                // temporarily registering listener
            });

            function testPayload(url, count, total) {
                casper.thenOpen(url, 
                {
                    method:"get",
                    headers:
                    {
                                'Cookie':cookieCli
                    }
                },
                function(status) 
                {
                    
                    var js = this.evaluate(function() {
                        return document;
                });

                //console.log('Trying => ' + url);

                    if (count === total - 1) {
                       //casper.echo('Scan Completed!', 'INFO');
                        console.log(vulns.length + ' payloads succeeded:\n');
                        if (vulns) 
                        {
                            console.log(vulns);

                                // if(pitserver)
                                // {
                                //     casper.thenOpen(pitserver,
                                //     {
                                //         method:"post",
                                //         data:
                                //         {
                                //             url:url.split('?')[0],
                                //             Result:vulns,
                                //             ID:ID
                                //         },
                                //         headers:
                                //         {'Content-Type': 'application/x-www-form-urlencoded'}
                                //     },
                                //     function(status)
                                //     {
                                //     });
                                //     casper.run();
                                // }
                            
                        }
                        else
                        {
                            console.log("hmm,it's look like no any clue");
                        }

                    }

                });

            }

            for (i = 0; i < payloads.length; i++) {
                testPayload(payloads[i], i, payloads.length);
            }
        }
    }
}
else
{
    var casperXSSPost = {

        detectParameters: function(postdata, analyze) {
            storedParamValues = postdata.split('&')
            detectedParameters = postdata.split('&');

            for (i = 0; i < detectedParameters.length; i++) {
                tempParam = detectedParameters[i].replace(/(=.*)/i, "");

                params.push(tempParam);
            }
            analyze();

        },

        analyze: function() {
            var setParameters = function(setpayloads) {
                for (i = 0; i < params.length; i++) {
                    //console.log("Detected the \"" + params[i] + "\" parameter, adding it into scope.");
                }
                setpayloads()
            }

            setParameters(this.setPayloads);
        },

            setPayloads: function() {
            for (z = 0; z < params.length; z++) {
                for (x = 0; x < xss.length; x++) {

                    var payloadString = params[z] + '=' + xss[x]
                    for (y = 0; y < params.length; y++) {
                        if(y != z){
                            payloadString += '&' + storedParamValues[y]
                        }
                    }
                    
                    payloads.push(payloadString);
                }
            }
           casperXSSPost.scan()
        },
           scan: function() {
            //console.log('\nTrying ' + payloads.length + ' payloads on a total of ' + params.length + ' parameter. \nSit back and enjoy the ride.\n');
            casper.start(url, function(status) {
            });
            casper.run()

            casper.then(function() {
                // temporarily registering listener
            });

            function testPayload(url,postdata, count, total) 
            {    
                
                casper.thenOpen(url, 
                    {
                        method:"post",
                        data:postdata,
                        headers:
                        {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Cookie':cookieCli

                        }
                    },
                function(status) 
                {
                        var js = this.evaluate(function() 
                        {
                            return document;
                        });
                        //console.log('Trying => ' + url);
                        if (count === total - 1) {
                            console.log(vulns.length + ' payloads succeeded:\n');

                            if (vulns) 
                            {
                                console.log(vulns)
                                // if(pitserver)
                                // {
                                //     casper.thenOpen(pitserver,
                                //     {
                                //         method:"post",
                                //         data:
                                //         {
                                //             url:url.split('?')[0],
                                //             Result:vulns,
                                //             ID:ID
                                //         },
                                //         headers:
                                //         {
                                //             'Content-Type': 'application/x-www-form-urlencoded',

                                //         }
                                //     },
                                //     function(status)
                                //     {
                                //     });
                                //     casper.run();
                                // }

                            }
                            else
                            {
                                
                                if(pitserver)
                                {
                                    casper.thenOpen(pitserver,
                                    {
                                        method:"post",
                                        data:
                                        {
                                            url:url.split('?')[0],
                                            Result:"NULL",
                                            ID:ID
                                        },
                                        headers:
                                        {'Content-Type': 'application/x-www-form-urlencoded'}
                                    },
                                    function(status)
                                    {
                                    });
                                    casper.run();
                     
                                }
                            }
                        }
                });
            }
            for (i = 0; i < payloads.length; i++) {
                testPayload(url,payloads[i], i, payloads.length);
            }
        }
    }
}
if (cookieCli) {
    cookies = cookieCli.split(";")
    for (i = 0; i < cookies.length; i++) {
        cookie = cookies[i].trim("")
        if (cookie){
            cookie = cookie.split("=")
            name = cookie[0]
            value = cookie[1]
            phantom.addCookie({
                'name': name,
                'value': value,
                'path':'/'
            })
        }
    }
}


if (!url) {
    // console.log('\nA valid URL is missing, please try again Ex: casperjs xss.js -u \"http://example.com?param1=vuln&param2=somevalue\"')
    // console.log('Currently casperXSS only supports GET requests and parameters within the query string...more to come');
    // console.log('\nIf your scan needs to be authenticated, currently you can import cookies via the --cookie option (similar to SQLmap)');
    // console.log('(Chrome extension \"Edit This Cookie\" works great at exporting to JSON)');
    // console.log('\ncasperXSS v0.1.0')
    casper.exit();
} 
if(casper.cli.has("postdata") == true)
{
    casperXSSPost.detectParameters(postdata, function() {
        casperXSSPost.analyze();
    });
}
else
{
    casperXSS.detectParameters(url, function() {
        casperXSS.analyze();
    });

}
