const mongoose = require('mongoose');
const config = require('config');
const db = config.get('mongoURI');


// - note, always use the try/catch with an async await
const connectDB = async () => {
    try {
        await mongoose.connect(db, {
            useNewUrlParser: true,
            useCreateIndex: true,
            useFindAndModify: false
        });
        console.log('MongoDB Connected...');
    } catch (err) {
        console.error(err.message);
        // Exit process with failure
        process.exit(1);

    }
}

module.exports = connectDB;