var mongoose = require('mongoose');
mongoose.connect('mongodb://localhost:27017/test');

mongoose.connection.on('error', (err) => {
    if (err) throw err;
    console.log("Something went wrong with MongoDB connection: ", err);
    process.exit();
});
mongoose.connection.once('open', () => {
    console.log("Connection established successfully for MongoDB");
});