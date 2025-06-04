const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const AppError = require('./../utils/appError');
const catchAsync = require('./../utils/catchAsync');
const Email = require('../utils/email');
const catchValidators = require('../utils/catchValidators');

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN, //additional security measure to protect the user data from being logged in
  });
};

const createSendToken = (user, res) => {
  const token = signToken(user._id);

  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000,
    ),
    // secure: true, //the cookie will only be sent on an encrypted connection (https)
    httpOnly: true, //this will make it that the  cannot be modified in anyway or accessed by the browser
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true; //the cookie will only be sent on an encrypted connection (https)

  // Set user password to undefined so it doesn't get returned as a response. remove user from the output
  user.password = undefined;

  res.cookie('jwt', token, cookieOptions);

  return token;
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    role: req.body.role,
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
    passwordChangedAt: req.body.passwordChangedAt,
  });

  const url = `${req.protocol}://${req.get('host')}/me`;
  console.log(url);
  await new Email(newUser, url).sendWelcome();

  const token = createSendToken(newUser._id, res);

  res.status(201).json({
    status: 'success',
    token,
    data: {
      user: newUser,
    },
  });
});

// in this case we only issue the token in case that the user actually exists, and that the password is correct.
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1. Check if email and password exist
  if (!email || !password) {
    return next(new AppError('Please provide email and password!', 400));
  }

  // 2. Check if user exists && password is correct
  const user = await User.findOne({
    email: email,
  }).select('+password'); //when creating the user through the user schema, the password was selected to be false, that means, we don't get it along with the data that will be sent back, but since we need it to implement the login feature, we have to use the select property here to get it
  //correctPassword is available to the user document as a method
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }
  //   console.log(user)

  // 3. if everything okay, send token to client
  const token = createSendToken(user._id, res);
  res.status(200).json({
    status: 'success',
    token, //
  });
});

exports.logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });
  res.status(200).json({ status: 'success' });
};

// PROTECTED ROUTES
exports.protect = catchAsync(async (req, res, next) => {
  let token;
  // 1. Getting token and Check if its there
  if (
    // this are the conditions under which we want to save a token
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    // if there was no token in the authorization header, then lets' take a look at the cookies
    token = req.cookies.jwt;
    // now we are able to authorize users based on tokens sent via cookie token and not only on the authorisation header
  }

  if (!token) {
    return next(
      new AppError('You are not logged in! Please login to get access.', 401),
    );
  }

  // 2. Verification token
  //   We are going to verify if someone manipulated the data or the token has already expired

  //   And so, we are actually going to promisifying this function jwt.verify().So basically, to make it return a promise. And so that way, we can then use async await just like any other async function that we've been using. So in order to do that, Node actually has a built-in promisify function. All we need to do in order to use it is to require the built-in util module.

  // jwt.verify is a function that takes a callback as its last argument.
  // We promisify jwt.verify itself, and then call the promisified version.
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // The original comment "as a third argument, this function actually requires a callback function. So this callback is then gonna run as soon as the verification has been completed."
  // refers to how jwt.verify needs to be structured for promisify to work on it.
  // So that result value of the promis will actually be the decoded data, so the decoded payload from this JSON web token

  // 3. Check if user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(
      new AppError('The user belonging to the token does no longer exist', 401),
    );
  }
  // currentUser = {
  //   _id: 681f5cc4ebf39954a82c9d98,
  //   name: 'old',
  //   email: 'hello@old.io',
  //   passwordChangedAt: 2025-07-30T00:00:00.000Z,
  //   __v: 0
  // }

  // 4. Check if user changed password after the token was issued
  const passwordChanged = await currentUser.changedPasswordAfter(decoded.iat);

  if (passwordChanged) {
    return next(
      new AppError('User recently changed password! Please log in again.', 401),
    );
  }

  if (true) {
    // console.log(passwordChanged);
  }

  //   iat means insured at.

  //   GRANT ACCESS TO PROTECTED ROUTE
  req.user = currentUser; //VERY CRUCIAL FOR US TO RUN OUR AUTHORIZATION CODE, ETC
  res.locals.user = currentUser; //VERY CRUCIAL FOR US TO RUN OUR AUTHORIZATION CODE, ETC
  next();
});

// ONLY FOR RENDERED PAGES AND THERE WILL BE NO ERROR
exports.isLoggedIn = async (req, res, next) => {
  try {
    // Our token should come from the cookies and not from an authorization header because, of course, for rendered pages we will not have the token in the header. So again, for our entire rendered website the token will always only be sent using the cookie, and never the authorization header.
    // 1. Getting token and Check if its there
    if (req.cookies.jwt) {
      //   And so, we are actually going to promisifying this function jwt.verify().So basically, to make it return a promise. And so that way, we can then use async await just like any other async function that we've been using. So in order to do that, Node actually has a built-in promisify function. All we need to do in order to use it is to require the built-in util module.

      // jwt.verify is a function that takes a callback as its last argument.
      // We promisify jwt.verify itself, and then call the promisified version.
      const decoded = await promisify(jwt.verify)(
        req.cookies.jwt,
        process.env.JWT_SECRET,
      );

      // The original comment "as a third argument, this function actually requires a callback function. So this callback is then gonna run as soon as the verification has been completed."
      // refers to how jwt.verify needs to be structured for promisify to work on it.
      // So that result value of the promis will actually be the decoded data, so the decoded payload from this JSON web token

      // 3. Check if user still exists
      const currentUser = await User.findById(decoded.id);
      if (!currentUser) {
        return next();
      }
      // currentUser = {
      //   _id: 681f5cc4ebf39954a82c9d98,
      //   name: 'old',
      //   email: 'hello@old.io',
      //   passwordChangedAt: 2025-07-30T00:00:00.000Z,
      //   __v: 0
      // }

      // 4. Check if user changed password after the token was issued
      const passwordChanged = await currentUser.changedPasswordAfter(
        decoded.iat,
      );

      if (passwordChanged) {
        return next();
      }

      //IF THERE ISN'T ANY CHANGED OF PASSWORD, THAT MEANS THERE IS A LOGGED IN USER THERE IS A LOGGED IN USER;
      //  each and every pug template will have access to response .locals and whatever we put there will then be a variable inside of these templates. So it's a little bit like passing data into a template using the render function.
      res.locals.user = currentUser; //VERY CRUCIAL FOR US TO RUN OUR AUTHORIZATION CODE, ETC
      return next();
    }
  } catch (err) {
    return next();
  }

  next(); //incase there is no cookie, then the next middleware will be called
};

// AUTHORISATION USING ROLE
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    // roles['admin', 'lead-guide']. role = 'user'
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403),
      );
    }

    next();
  };
};

// PASSWORD RESET
exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1. GET USER BASED ON POSTED EMAIL
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError('There is no user with email address', 404));
  }

  // 2. GENERATE RANDOM RESET
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false }); //no need in validating the documents again before saving the document

  try {
    // SEND IT TO USER'S EMAIL(create an instand method with the)
    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`; //for testing purpose, during development, idealy the reset URL is to be activated when a user clicks reset password

    await new Email(user, resetURL).sendPasswordReset();

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!',
    });
  } catch (error) {
    // incase there is an error, we want to reset both the token and the password expires property
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    // then we have to save it into the document after modifying it
    await user.save({ validateBeforeSave: false });
    console.log(error);

    return next(
      new AppError(
        'There was an error sending the email, Try again Later',
        500,
      ),
    );
  }
});

// RESET PASSWORD HANDLER
exports.resetPassword = catchAsync(async (req, res, next) => {
  //Defining the variables
  let response = res;

  // 1.Get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex'); //req.params.token is gotten from the forgotPassword URL that was called

  // The only thing that identify the user is the token because we don't know which user is reseting their password
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  }); //This is the way we can get the user to implement our update/reset password functionality

  // 2.If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  try {
    await user.save();
  } catch (error) {
    catchValidators(error, response);
    return;
  }

  // 3.Update changePasswordAt property for the user
  // This was done at the userModel.js file using a presave Middleware. Check the userModel.js file for clarity

  // 4. Log the user in, send JWT
  const token = createSendToken(user._id, res);

  res.status(200).json({
    status: 'success',
    token,
  });
});

// ALLOWING A LOGGED IN USER TO UPDATE HIS PASSWORD
exports.updatePassword = catchAsync(async (req, res, next) => {
  // The password updating functionality is only for logged in users
  //Defining the variables

  // 1. Get User from collection
  let response = res;
  const user = await User.findById(req.user.id).select('+password');
  // 2. Check if POSTed current password is correct
  if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
    return next(new AppError('Your Current password is wrong'), 401);
  }

  // 3. If so, update password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;

  try {
    await user.save();
  } catch (error) {
    catchValidators(error, response);
    return;
  }
  // 4. Log user in, send JWT
  const token = createSendToken(user._id, res);

  res.status(200).json({
    status: 'success',
    token,
  });
});
