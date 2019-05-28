const express = require('express');
const router = express.Router();
const bcryprt = require('bcryptjs');
const passport = require('passport');

//User Model

const User = require('../models/User');

//Login Page

router.get('/login', (req,res) => res.render('Login'));

//Register Page
router.get('/register', (req, res)=> res.render('Register'));

//Register Handle ~~ signup

router.post('/register', (req,res) => {
    const {name, email, password, password2} = req.body;
    let errors = [];

    //Validation
    //Validation1 => check required fields
    if (!name || !email || !password || !password2){
        errors.push({msg: 'Please fill all the fields'});
    }

     //Validation 2 => PASSWORD NOT MATCH
     
     if( password !== password2){
         errors.push({msg:  'Passwords do not match'});
     }

     //Validation 3 => PASSWORD Length

     if(password.length <6){
         errors.push({msg: 'Password should be atleast 6 charectrs'});
     }

     if(errors.length >0){
         res.render('register',{
             errors,
             name,
             email,
             password,
             password2
         });
     } else {
        //validation passed
        User.findOne({email:email})
        .then(user =>{
            //If Useremail already register exists. go back to register
            if(user){
                errors.push({msg:'email is already register'});
                res.render('register',{
                    errors,
                    name,
                    email,
                    password,
                    password2
                });
            } else    {                //create new user with bcrypt pass)
                const newUser = new User({
                    name:name,
                    email:email,
                    password:password
                });
               //Hash Password
                bcryprt.genSalt(10,(err,salt) => 
                bcryprt.hash(newUser.password, salt, (err,hash) =>  {
                        if(err) throw err;
                        //password set to hash
                        newUser.password = hash;
                        //save user 
                        newUser.save()
                               .then(user => {
                                   req.flash('success_msg', 'You are now registered and do Login');
                                   res.redirect('/users/login')  
                                })
                               .catch(err => console.log(err))
                              }));
               }
            
            
        });
     }

});

//Login handle

router.post('/login', (req, res, next)=> {
    passport.authenticate('local',{
    successRedirect: '/dashboard',
    failureRedirect: '/users/login',
    failureFlash:true
    })(req,res,next);
});

//Logout Handle

router.get('/logout', (req,res)=>{
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');
})


module.exports = router;