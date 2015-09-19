var mongoose = require('mongoose');
var host = new mongoose.Schema(
    {
        Header:{},
        Post: String,
        IP: String,
        Scheme: String,
        Method: String,
        Port: String,
        Path:String,
    });


var hostinfo = mongoose.model('AllData',host,'AllData');

module.exports = hostinfo;
//实例化