// var mongoose = require('mongoose');
// var test = new mongoose.Schema(
//     {
//         Header:{},
//         OriginPost: String,
//         IP: String,
//         Scheme: String,
//         Method: String,
//         EditedPost: String,
//         Port: String,

        
//     });


// var test = mongoose.model('AllData',test,'AllData');
// var TestDAO = function(){};


// TestDAO.prototype.findPagination = function(obj,callback) {
//   var q=obj.search||{}
//   var col=obj.columns;

//   var pageNumber=obj.page.num||1;
//   var resultsPerPage=obj.page.limit||10;

//   var skipFrom = (pageNumber * resultsPerPage) - resultsPerPage;
//   var query = test.find(q,col).sort('-create_date').skip(skipFrom).limit(resultsPerPage);

//   query.exec(function(error, results) {
//     if (error) {
//       callback(error, null, null);
//     } else {
//       test.count(q, function(error, count) {
//         if (error) {
//           callback(error, null, null);
//         } else {
//           var pageCount = Math.ceil(count / resultsPerPage);
//           callback(null, pageCount, results);
//         }
//       });
//     }
//   });
// }

// //module.exports = test;
// //实例化