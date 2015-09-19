var host = require('./host.js');
var mongoose = require('mongoose');
var payload = new mongoose.Schema(
    {
        Payload: String,
        All_ID: mongoose.Schema.Types.ObjectId,
        Host:String,
        Path: String,
        timestamp:Number,
    });

payload.methods.getscheme = function()
{
    console.log("search fucking xxx");
    return host.findOne({"_id":this.All_ID},function(err,result)
        {
            return {

                Scheme:result.Scheme,

            }
        });
};

var payloads = mongoose.model('Payload',payload,'Payload');

module.exports = payloads;
//实例化