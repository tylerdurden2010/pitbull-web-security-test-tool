var express = require('express');
var mongoose = require('mongoose');

var log4js = require('log4js');
log4js.configure({
  appenders: [
    {
      type: 'file',
      filename: '/tmp/access.log', 
      maxLogSize: 1024,
      backups:3,
      category: 'normal' 
    }
  ]
});
var logger = log4js.getLogger('normal');
logger.setLevel('INFO');

var app = express();
app.use(require('body-parser')());


Hosts = require('./models/host.js');
PayLoads = require('./models/payload.js');
SQLTest = require('./models/sqlattack.js');
XssTest = require('./models/xssTest.js');
CsrfTest = require('./models/csrfattack.js');


var spawn = require('child_process').spawn;
//链接数据库
var uristring =
process.env.MONGOLAB_URI ||
process.env.MONGOHQ_URL ||                          
'mongodb://localhost/scanner';
//

var handlebars = require('express-handlebars').create({ defaultLayout:'main' });
app.engine('handlebars',handlebars.engine);
app.set('view engine','handlebars')
app.set('port', process.env.PORT || 3000);

app.use(express.static(__dirname + '/public'));




app.get('/',function(req,res)
    {
        res.render('home');
    });

app.get('/cleanall',function(req,res)
    {
        
        Hosts.remove({}, function(err) { 
            logger.info('collection removed') 
        });

        SQLTest.remove({},function(err){
            logger.info(err);
        });

        CsrfTest.remove({},function(err){
            logger.info(err);
        });
        XssTest.remove({},function(err){
        logger.info(err);
        });
        PayLoads.remove({},function(err){
            logger.info(err);
        });
        return res.redirect(303,'/');

    });

app.get('/list/search',function(req,res)
    {
        var reg = new RegExp()
        reg = /((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)/;
        // var hostname = req.params.thehost;
        var param = req.query.param;
        if(param)
        {

            if(reg.test(param))
            {
                Hosts.find({"IP":param},function(err,AllData)
                    { 
                    var context ={          
                            AllData:AllData.map
                            (function(test)
                            {
                                if (!!test.IP) {
                                   return {
                                        IP:test.IP,
                                        Scheme:test.Scheme,
                                        Host:test.Header.Host,
                                        ID:test._id,
                                    }               
                                };
                            })
                        };
                        var arr = {};           
                        for (var i =0; i<context.AllData.length; i++)
                        {
                            arr[context.AllData[i]['Host']] = new Array();
                        }
                        for (var i = 0; i < context.AllData.length; i++)
                        {
                            arr[context.AllData[i]['Host']][context.AllData[i]['IP']] = context.AllData[i];
                        }
                                        
                        context.AllData = new Array();      
                        for (var key in arr)
                            for (var key2 in arr[key])
                            context.AllData.push(arr[key][key2]);
                        context.Len = new Array();
                        context.Len.push(context.AllData.length);
                        res.render('list', context);

                    });
            }
            else
            {
                var re = new RegExp(param,'i');
                Hosts.find({"Header.Host":{ $regex:re }},function(err,AllData){
                      var context ={          
                            AllData:AllData.map
                            (function(test)
                            {
                                if (!!test.IP) {
                                   return {
                                        IP:test.IP,
                                        Scheme:test.Scheme,
                                        Host:test.Header.Host,
                                        ID:test._id,
                                    }               
                                };
                            })
                        };
                        var arr = {};           
                        for (var i =0; i<context.AllData.length; i++)
                        {
                            arr[context.AllData[i]['Host']] = new Array();
                        }
                        for (var i = 0; i < context.AllData.length; i++)
                        {
                            arr[context.AllData[i]['Host']][context.AllData[i]['IP']] = context.AllData[i];
                        }
                                        
                        context.AllData = new Array();      
                        for (var key in arr)
                            for (var key2 in arr[key])
                            context.AllData.push(arr[key][key2]);
                        context.Len = new Array();
                        context.Len.push(context.AllData.length);
                        res.render('list', context);
                });

            }
        }


    });

app.get('/list', function(req, res) {

        Hosts.find().sort({Timestamp:'-1'}).exec(function(err,AllData)
            {
                var context ={          
                    AllData:AllData.map
                    (function(test)
                    {
                        if (!!test.IP) {
                           return {
                                IP:test.IP,
                                Scheme:test.Scheme,
                                Host:test.Header.Host,
                                ID:test._id,
                            }               
                        };
                    })
                };
                var arr = {};           
                for (var i =0; i<context.AllData.length; i++)
                {
                    arr[context.AllData[i]['Host']] = new Array();
                }
                for (var i = 0; i < context.AllData.length; i++)
                {
                    arr[context.AllData[i]['Host']][context.AllData[i]['IP']] = context.AllData[i];
                }
                //Len is the count of tagets
                context.AllData = new Array();      
                for (var key in arr)
                    for (var key2 in arr[key])
                    context.AllData.push(arr[key][key2]);
                context.Len = new Array();
                context.Len.push(context.AllData.length);
                res.render('list', context);
            });
        });




app.get('/payload',function(req,res)
    {
        res.render('payload');
    });

//This interface is using for display host information where displayed on the payload
//It's also depends on the Jquery function
app.get('/payload/host/:newid',function(req,res)
    {
        var newid = req.params.newid;
        Hosts.findOne({"_id":newid},function(err,HostName)
            {
 
                    res.json({Hostname:HostName.Header.Host,Path:HostName.Path,Method:HostName.Method,Header:HostName.Header,
                        Cookie:HostName.Cookie,Scheme:HostName.Scheme,Port:HostName.Port,IP:HostName.IP,PostData:HostName.Post}); 
                });
    });   


app.get('/payload/:ID?',function(req,res)
    {
        var ID = req.params.ID;
        Hosts.findOne({"_id":ID},function(err,HostName)
            {
                Domain = HostName.Header.Host;
                CurrentScheme = HostName.Scheme;
                //First genreate hostname
                //second find hostname and the payloads 
                //the paylods was generated by proxy
                PayLoads.find({"Host":Domain}).sort({Timestamp:'-1'}).exec
                (function(err,AllPayload){

                     var context =
                    {                      
                        AllPayload:AllPayload.map
                        (function(test)
                        {
                            //console.log(fuck);
                            return {
                                Path:test.Path,
                                Payload:test.Payload,

                                //##########################################################
                                //# This ID is the AllData single ID, it's using for searching 
                                //# one special origin HTTP request.
                                //##################################################
                                ID: test.All_ID,
                                


                                // Scheme: Hosts.findOne({"_id":test.All_ID},function(err,IDs)
                                //     {
                                    
                                //         var fuck = {

                                //             IDs:IDs.map(
                                //                 function
                                //                 )


                                }               
                            }),Host:Domain
                    };
                    res.render('payload',context); 



                });

               // PayLoads.find({"Host":Domain},function(err,AllPayload)
               //  {
  
               //      var context =
               //      {                      
               //          AllPayload:AllPayload.map
               //          (function(test)
               //          {
               //              //console.log(fuck);
               //              return {

               //                  Path:test.Path,
               //                  Payload:test.Payload,
               //                  ID: test.All_ID,
                                


               //                  // Scheme: Hosts.findOne({"_id":test.All_ID},function(err,IDs)
               //                  //     {
                                    
               //                  //         var fuck = {

               //                  //             IDs:IDs.map(
               //                  //                 function
               //                  //                 )


               //                  }               
               //              }),Host:Domain
               //      };
               //      res.render('payload',context); 
               //  });
            });
    });


app.post('/sqlattack',function(req,res){

    var datasave = new SQLTest({
        Header:JSON.parse(req.body.Header),
        Scheme:req.body.Scheme,
        Method:req.body.Method,
        Path:req.body.Path,
        Payload:req.body.Payload,
        Port:req.body.Port,
        IP:req.body.IP,
        OriginID:req.body.OriginID,
        Level:req.body.Level,
        Dbms:req.body.Dbms,
    });

    datasave.save(function(err,datasave){
        //console.log(datasave.id);
        var zmq = require('zmq');
        var client = zmq.socket('pair');
        client.connect("tcp://localhost:5555");
        //When the save function return the id , node will send the ID to zmq,which running on the background
        //datasave.id + type
        //sql,0; XSS,1; CSRF,2;
        request = datasave.id + ":" + "0";
        client.send(request);
        client.close();
        if(err)
            return console.error(err);
});

    var redirect = '/payload/'+req.body.OriginID;


    return res.redirect(303,redirect);

});

app.post('/xssattack',function(req,res){
    var datasave = new XssTest({
        Header:JSON.parse(req.body.Header),
        Scheme:req.body.Scheme,
        Method:req.body.Method,
        Path:req.body.Path,
        Payload:req.body.Payload,
        Port:req.body.Port,
        IP:req.body.IP,
        OriginID:req.body.OriginID,
    });

    datasave.save(function(err,datasave){
        //console.log(datasave.id);
        var zmq = require('zmq');
        var client = zmq.socket('pair');
        //sql,0; XSS,1; CSRF,2;
        request = datasave.id + ":" + "1";
        client.connect("tcp://localhost:5555");
        //When the save function return the id , node will send the ID to zmq,which running on the background
        //datasave.id + type
        client.send(request);
        client.close();
        if(err)
            return console.error(err);
});

    var redirect = '/payload/'+req.body.OriginID;


    return res.redirect(303,redirect);

});

app.get('/xss',function(req,res){
   XssTest.find().sort({Timestamp:'-1'}).exec(function(err,data)
   {
    if(err)
    {
        console.log('Error');
    }
    else
    {
         var context = 
        {
            data:data.map(function(xssstatus){
                return{
                    Host:xssstatus.Header.Host,
                    Scheme:xssstatus.Scheme,
                    Result:JSON.stringify(xssstatus.Result),
                    Path:xssstatus.Path,
                    Method:xssstatus.Method,
                }
            })
        };
        res.render('xss',context);    
    }


   });

});
app.get('/csrf',function(req,res){
   CsrfTest.find().sort({Timestamp:'-1'}).exec(function(err,data)
   {
    if(err)
    {
        console.log('Error');
    }
    else
    {
         var context = 
        {
            data:data.map(function(csrf){
                return{
                    Host:csrf.Header.Host,
                    Scheme:csrf.Scheme,
                    Result:JSON.stringify(csrf.Result),
                    Path:csrf.Path,
                    Method:csrf.Method,
                }
            })
        };
        res.render('csrf',context);    
    }


   });

});
// app.post('/xssresultsave',function(req,res)
//     {
//         var ID = req.body.ID;
//         XssTest.findOne({"_id":ID},function(err,OneData)
//         {   
            
            
//             OneData.Result = req.body.Result;

//             OneData.save(function(err)
//                 {
//                     if(err)
//                         return handleError(err);
//                     res.sendStatus(200);
//                 });
//             //alldata.Result = req.body.Result;
  
//         });

//         return res.sendStatus(200);

//     });

app.post('/csrfattack',function(req,res){
    var datasave = new CsrfTest({
        Header:JSON.parse(req.body.Header),
        Scheme:req.body.Scheme,
        Method:req.body.Method,
        Path:req.body.Path,
        Payload:req.body.Payload,
        Port:req.body.Port,
        IP:req.body.IP,
        OriginID:req.body.OriginID,
    });

    datasave.save(function(err,datasave){
        //console.log(datasave.id);
        var zmq = require('zmq');
        var client = zmq.socket('pair');
        //sql,0; XSS,1; CSRF,2;
        request = datasave.id + ":" + "2";
        client.connect("tcp://localhost:5555");
        //When the save function return the id , node will send the ID to zmq,which running on the background
        //datasave.id + type
        client.send(request);
        client.close();
        if(err)
            return console.error(err);
});

    var redirect = '/payload/'+req.body.OriginID;

    return res.redirect(303,redirect);

});


app.get('/sqlinjection',function(req,res){
   SQLTest.find().sort({Timestamp:'-1'}).exec(function(err,data)
   {
    if(err)
    {
        console.log('Error');
    }
    else
    {
         var context = 
        {
            data:data.map(function(sqlstatus){
                return{
                    Host:sqlstatus.Header.Host,
                    Scheme:sqlstatus.Scheme,
                    Result:JSON.stringify(sqlstatus.Result),
                    Level:sqlstatus.Level,
                    Path:sqlstatus.Path,
                    Method:sqlstatus.Method,
                    Dbms:sqlstatus.Dbms,
                }
            })
        };
        res.render('sqlinjection',context);    
    }


   });

});


mongoose.connect(uristring, function (err, res) {
  if (err) {
  console.log ('ERROR connecting to: ' + uristring + '. ' + err);
  } else {
  console.log ('Succeeded connected to: ' + uristring);
  }
});

// testdatabase
PayLoads.find({"All_ID":'55ac6d42e138233ab50cb6c0'},function(err,AllData)
{
         // console.log(AllData);

    // if(AllData.length)
    //     return;

});


app.listen(app.get('port'), function(){
  console.log( 'Express started on http://localhost:' + 
    app.get('port') + '; press Ctrl-C to terminate.' );
});
