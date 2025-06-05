// MONGOOSE DATABASE
const mongoose = require('mongoose');
// DOT ENV MODULE
const dotenv = require('dotenv');
// SETTING THE ENVIRONMENT VARIABLE from the './config.env file'
dotenv.config({ path: './config.env' });

// HANDLING UNCAUGHT EXCEPTION
process.on('uncaughtException', (err) => {
  console.log('Unandle Exception... Shutting down');
  console.log(err.name, err.message);
  process.exit(1);
});

// definining the app from './app' folder
const app = require('./app');

// DATABASE RELATED
// THE DATABASE RESTFUL API WAS BUILT BEFORE ADDING THE DATABASE
// REPLACEING THE PASSWORD ON THE CONNECTION STRING WITH THE ONE STORED ON THE ENV VARIABLE
const DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD,
);

// CONNECTING THE DATABASE TO THE APP (DATABASE RELATED)
mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true,
  })
  .then((con) => {
    console.log('the connection is successfully made');
  });

// //////////////////////////////////////////////////////////////
// ENVIRONMENT VARIABLES
// console.log(app.get('env'));
// console.log(process.env.JWT_SECRET);

// We can define an env variable into the environment by running the code nodemon on the command line when starting the app
// e.g
// NODE_ENV=development nodemon server.js
// NODE_ENV=development X=23 nodemon server.js (can add more than 1 variable into the environment)

// It is not adviceable to run these on the command line, when you have more than just 2 env variable, to accomplish this, we have to create a config file

// CREATING A NEW SERVER
const port = process.env.PORT || 3000;
// app.listen was converted to having stored on a variable so we can use in our unhandledRejection event listener
const server = app.listen(port, () => {
  console.log(`App is listening on port ${port}`);
});

// HANDLING UNHANDLE PROMISE
process.on('unhandledRejection', (err) => {
  // If we have an error or problem with the database connection, we should go ahead and shut the application
  console.log('Unandle Rejection... Shutting down');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1); //And so by doing this, by doing server.close, we give the server, basically time to finish all the reques that are still pending or being handled at the time and only after that, the server is then basicall killed, all right?
  });

  // code 0 = success
  // code 1 = uncaught exception
});

process.on('SIGTERM', () => {
  console.log('SIGTERM RECEIVED. Shutting down gracefully');
  server.close(() => {
    console.log('💥 Process terminated');
  });
});
// process is a global object in Node.js that provides information about, and control over, the current Node.js process.
// .on('SIGTERM', callback) is an event listener. It tells Node.js: "When the operating system sends a SIGTERM signal to this process, execute the provided callback function."
// SIGTERM is a signal asking the process to terminate. It's a "polite" request, unlike SIGKILL which forces termination immediately. SIGTERM gives the application a chance to shut down gracefully.
// console.log('SIGTERM RECEIVED. Shutting down gracefully');

// This line simply logs a message to the console, indicating that the SIGTERM signal has been received and the application is beginning its shutdown procedure. This is helpful for debugging and monitoring.
// server.close(() => { ... });

// This is the core of the graceful shutdown. server (which was defined earlier in your server.js file as const server = app.listen(...)) refers to your HTTP server instance.
// server.close() stops the server from accepting new incoming connections.
// Crucially, it also waits for any existing, currently active connections to finish their ongoing requests before actually closing. This prevents abruptly cutting off users who are in the middle of something.

// i.e
// It acknowledges the signal.
// It stops accepting new requests.
// It allows any ongoing requests to complete.
// It then cleanly shuts down the server.
// Finally, it logs that the process has terminated.

// STATUS CODE
// 200 = OK
// 201 = CREATED
// 204 = NO CONTENT
//401 = Unathorised
// 500 = Internal server error
