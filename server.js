const express = require('express');
const multer = require('multer');
const cors = require('cors'); 
const path = require('path');
const mongoose = require('mongoose');
const fs = require('fs');
const bcrypt = require('bcrypt'); 
const SALT_ROUNDS = 10; 
const jwt = require('jsonwebtoken'); 
const crypto = require('crypto');   
const nodemailer = require('nodemailer'); 

const app = express();
// NEW: Use express.json() middleware for parsing JSON bodies in API requests
app.use(express.json());

// --- MONGODB CONNECTION SETUP ---
// 2. Retrieve URI and JWT Secret from environment variables
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL; 
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD; 

// --- 1. EMAIL TRANSPORT SETUP ---
// Configuration to connect to an SMTP service (e.g., Gmail using an App Password)
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: process.env.EMAIL_PORT || 465,
    secure: process.env.EMAIL_PORT == 465 || true, 
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS, 
    },
});

// 1. User/Client Account Schemas (Updated for UserID Name and Password)
const accountSchema = new mongoose.Schema({
    currencyCode: { type: String, required: true },
    accountNumber: { type: String, required: true, unique: true },
    domesticRouting: { type: String, required: true },
    iban: { type: String },
    domesticLabel: { type: String },
    balance: { type: Number, default: 0.00 },
    swift: { type: String },
    // 🚨 UPDATED: Added account type to distinguish checking/savings
    accountType: { type: String, required: true, enum: ['Checking', 'Savings'] },
    
    // 🔑 CRITICAL ADDITION: Overdraft Limit
    overdraftLimit: { 
        type: Number, 
        default: 0.00, 
        min: 0 
    } 
}, { 
    _id: false, 
    // ⭐ CRITICAL FIX: Ensure Mongoose explicitly saves fields with default values, 
    // even if they are 0.00, to prevent them from being stripped from the DB document.
    minimize: false 
}); 


const announcementMessageSchema = new mongoose.Schema({
    type: { type: String, default: 'ANNOUNCEMENT', enum: ['ANNOUNCEMENT'], required: true },
    isActive: { type: Boolean, default: false },
    messageContent: { 
        type: String, 
        default: '', 
        trim: true 
        // Removed the invalid '...' and the trailing comma
    }, 
    lastUpdatedByAdmin: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }, 
    lastUpdatedAt: { type: Date, default: Date.now }
}, { _id: false });

const transferMessageSchema = new mongoose.Schema({
    isActive: { 
        type: Boolean, 
        default: false 
    },
    messageContent: { 
        type: String, 
        trim: true,
        default: ''
    },
    // Tracking who set it and when
    lastUpdatedByAdmin: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Admin',
        default: null
    },
    lastUpdatedAt: {
        type: Date,
        default: Date.now
    }
}, { _id: false });


// --- USER SCHEMA DEFINITION ---

// --- UPDATED USER SCHEMA DEFINITION ---
const userSchema = new mongoose.Schema({
    // ... (rest of the user schema fields) ...
    userIdName: { 
        type: String, 
        required: true, 
        unique: true, 
        trim: true, 
        minlength: 5, 
        set: (v) => v.toLowerCase()
    }, 
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        validate: {
            validator: function(v) {
                return /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(v);
            },
            message: props => `${props.value} is not a valid email address!`
        }
    },
    passwordHash: { type: String, required: true }, 
    transferPinHash: { type: String, required: true },
    otpHash: { type: String, default: null },
    otpExpiration: { type: Date, default: null },
    fullName: { type: String, required: true },
    dob: { type: Date, required: true },
    gender: { type: String }, 
    address: { type: String, required: true },
    occupation: { type: String, required: true },
    profilePicturePath: { type: String, default: null },
    
    accounts: [accountSchema], 
    
    // ⭐ NEW FIELD: Announcement Message Configuration
    announcementMessage: {
        type: announcementMessageSchema,
        // Initialize with an empty object so the sub-document structure exists
        // and default values from announcementMessageSchema are applied.
        default: () => ({}) 
    },
    
    transferMessage: {
        type: transferMessageSchema,
        default: () => ({}) 
    },
    
    createdAt: { type: Date, default: Date.now },
    status: { type: String, default: 'Active' },
    currency: { type: String, required: true },
    role: {
        type: String,
        required: true,
        default: 'User',
        enum: ['User', 'Admin', 'Support'] 
    },
});

const User = mongoose.model('User', userSchema);


// 2. ADMIN ACCOUNT Schema
const adminSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true }, 
    passwordHash: { type: String, required: true }, 
    role: { type: String, default: 'BasicAdmin' },
    createdAt: { type: Date, default: Date.now }
});

const Admin = mongoose.model('Admin', adminSchema); 

// Server-Side: cardSchema in your Mongoose setup file (server.js:195)
const cardSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    cardHolderName: { type: String, required: true, uppercase: true },
    cardNumber: { type: String, required: true, unique: true },
    expiryDate: { type: String, required: true },
    cvv: { type: String, required: true },
    
    // ✅ This 'status' field definition is correct.
    status: {
        type: String,
        // The enum defines all allowed string values, including both cases.
        enum: ['ACTIVE', 'FROZEN', 'Active', 'Frozen'], 
        default: 'ACTIVE' // Nested correctly inside the status object.
    },
    
    // Metadata for admin tracking
    generatedByAdmin: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
    generatedAt: { type: Date, default: Date.now },
}, { collection: 'cards' });

const Card = mongoose.model('Card', cardSchema);

// 3. Check Deposit Schema (NEW)
const checkDepositSchema = new mongoose.Schema({
    // Deposit Tracking and Status
    depositId: { 
        type: String, 
        required: true, 
        unique: true, 
        trim: true 
    }, 
    status: { 
        type: String, 
        required: true, 
        default: 'Pending', 
        enum: ['Pending', 'Approved', 'Declined'] 
    },
    
    // User Identification
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    username: { 
        type: String, 
        required: true 
    }, // Stored for faster administrative queries

    // Financial Details
    amount: { 
        type: Number, 
        required: true, 
        min: 0.01 
    },
    currencyCode: { 
        type: String, 
        required: true, 
        uppercase: true 
    },
    
    // Image References
    imageFrontUrl: { 
        type: String, 
        required: true 
    },
    imageBackUrl: { 
        type: String, 
        required: true 
    },

    // Administrative Review and Timestamps
    reviewedByAdmin: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Admin', 
        default: null 
    },
    reviewNotes: { 
        type: String, 
        default: '' 
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    },
    updatedAt: { 
        type: Date, 
        default: Date.now 
    },
}, { 
    collection: 'checkdeposits' 
});

const CheckDeposit = mongoose.model('CheckDeposit', checkDepositSchema);

// --- 7. Transaction Schema (FIXED) ---
const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    date: { type: Date, default: Date.now },
    // Positive (+) for Credits, negative (-) for Debits.
    amount: { type: Number, required: true }, 
    description: { type: String, required: true },
    accountNumber: { type: String, required: true },
    accountType: { type: String, required: true, enum: ['Checking', 'Savings'] },
    referenceId: { type: String, unique: true }, 
    
    // ⭐ CRITICAL FIX: Re-adding these fields for internal transfer completion logic
    destinationAccountNumber: { type: String, required: false }, 
    isInternal: { type: Boolean, default: false }, 
    
    // Status Management
    status: { 
        type: String, 
        required: true, 
        default: 'Processing', 
        enum: ['Processing', 'Pending', 'Approved', 'Successful', 'Delivered', 'Refunded', 'Failed', 'Declined'] 
    },
    lastUpdatedByAdmin: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }, 
    updatedAt: { type: Date, default: Date.now } 
});

const Transaction = mongoose.model('Transaction', transactionSchema);


// ----------------------------------------------------
// --- NEW ACCOUNT GENERATION & RETRY LOGIC (FIX) ---
// ----------------------------------------------------

/** Helper function to introduce a small delay */
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Generates account details, retrying the generation until a number 
 * unique across all users in the database is confirmed.
 * This prevents E11000 errors on the 'accountNumber' unique index.
 */
async function generateUniqueAccountDetails(User, currency, type, initialBalance) {
    let attempts = 0;
    const MAX_ATTEMPTS = 10; // Increased attempts for higher confidence in uniqueness

    while (attempts < MAX_ATTEMPTS) {
        // 1. Use the existing synchronous logic to create an account object
        const accountDetails = generateAccountDetails(currency, type, initialBalance);
        const newAccountNumber = accountDetails.accountNumber;
        
        // 2. Check if the generated account number already exists in *any* user's accounts array
        const existingUser = await User.findOne({
            'accounts.accountNumber': newAccountNumber
        }).select('_id').lean().exec();

        if (!existingUser) {
            // Success: Number is unique, return the complete account object
            return accountDetails;
        }

        // Failure: Collision detected. Log and retry.
        console.warn(`[Collision] Account number ${newAccountNumber} already exists. Retrying... (Attempt ${attempts + 1})`);
        attempts++;
        await sleep(50 * attempts); // Exponential backoff in wait time
    }

    // If we fail after max attempts, throw an error to trigger the 500 response
    throw new Error('Failed to generate a unique bank account number after maximum attempts.');
}


// ----------------------------------------------------------------------------------
// --- MIDDLEWARE SETUP (CORS, Static Files, Multer, Helpers) (Existing code) ---
// ----------------------------------------------------------------------------------

// Helper for random number generation
const getRandomAmount = (min, max) => {
    return (Math.random() * (max - min) + min).toFixed(2);
};

// Helper for random description generation (uses the request body pattern if provided)
const getRandomDescription = (isCredit, descriptionPattern = "Mock Transaction at Merchant X") => {
    const merchants = ["Amazon", "Walmart", "Starbucks", "Gas Station", "Payroll"];
    const descriptions = [
        "Payment to", "Purchase from", "Transfer to", "ATM Withdrawal", "Deposit from"
    ];

    if (isCredit) {
        return `Deposit: ${descriptions[4]} Company Y`;
    }
    
    // Debit transaction
    const baseDesc = descriptionPattern.replace('Merchant X', merchants[Math.floor(Math.random() * merchants.length)]);
    return `${descriptions[Math.floor(Math.random() * 3)]} ${baseDesc}`;
};

// Helper for generating a random date between two Date objects
const getRandomDate = (start, end) => {
    // Convert dates to timestamps (milliseconds)
    const startTime = start.getTime();
    const endTime = end.getTime();
    
    // Generate a random timestamp within the range
    const randomTime = startTime + Math.random() * (endTime - startTime);
    
    return new Date(randomTime);
};
// 1. CORS
app.use(cors());


// Configure Multer for file uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // Use a unique filename
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });


// 3. Helper to generate mock account details (Existing logic)
// 🚨 NOTE: This function is now used by generateUniqueAccountDetails to create a candidate object.
const generateAccountDetails = (currencyCode, accountType, initialBalance = 0.00) => {
    let accountNumber = '';
    let domesticRouting = ''; 
    let iban = '';
    let swiftCode = '';
    
    const currencyConfig = {
        'USD': { domesticLabel: 'ABA Routing Number', ibanPrefix: '', swift: 'BANKUSNY' },
        'EUR': { domesticLabel: 'IBAN', ibanPrefix: 'DE', swift: 'BANKDEFF' },
        'GBP': { domesticLabel: 'Sort Code', ibanPrefix: 'GB', swift: 'BANKGB2L' },
        'AUD': { domesticLabel: 'BSB Number', ibanPrefix: 'AU', swift: 'BANKAU2S' },
        'CAD': { domesticLabel: 'Transit/Institution No.', ibanPrefix: 'CA', swift: 'BANKCA3V' }
    };

    const c = currencyConfig[currencyCode] || {};
    swiftCode = c.swift;

    const generateRandomNumber = (length) => {
        let result = '';
        const characters = '0123456789';
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * characters.length));
        }
        return result;
    };

    // Use the account type to create a slight variation in the account number for clarity
    const typePrefix = accountType === 'Checking' ? '1' : (accountType === 'Savings' ? '5' : '9');
    const seed = Date.now().toString().slice(-4); 

    switch (currencyCode) {
        case 'USD':
            accountNumber = typePrefix + generateRandomNumber(5) + seed; // 1xxxx xxxx or 5xxxx xxxx
            domesticRouting = generateRandomNumber(9);
            iban = `N/A (Wire Routing: ${domesticRouting})`;
            break;
        case 'EUR':
            domesticRouting = 'N/A (Covered by IBAN)';
            accountNumber = typePrefix + generateRandomNumber(5) + seed;
            iban = c.ibanPrefix + generateRandomNumber(18) + seed.substring(0,2);
            break;
        case 'GBP':
            accountNumber = typePrefix + generateRandomNumber(3) + seed;
            domesticRouting = generateRandomNumber(2) + '-' + generateRandomNumber(2) + '-' + generateRandomNumber(2);
            iban = c.ibanPrefix + generateRandomNumber(20);
            break;
        case 'AUD':
            accountNumber = typePrefix + generateRandomNumber(4) + seed;
            domesticRouting = generateRandomNumber(3) + '-' + generateRandomNumber(3);
            iban = c.ibanPrefix + generateRandomNumber(20);
            break;
        case 'CAD':
            accountNumber = typePrefix + generateRandomNumber(2) + seed;
            domesticRouting = generateRandomNumber(5) + ' / ' + generateRandomNumber(3);
            iban = `N/A (Transit: ${domesticRouting.split(' / ')[0]})`;
            break;
        default:
            accountNumber = typePrefix + generateRandomNumber(11);
            domesticRouting = 'N/A';
            iban = 'N/A';
    }

    return { 
        currencyCode,
        accountNumber, 
        domesticRouting, 
        iban,
        domesticLabel: c.domesticLabel,
        swift: swiftCode,
        balance: initialBalance, // 🚨 Now uses the initialBalance argument
        accountType // 🚨 Added accountType
    };
};

// 4. Helper function to remove a profile picture file
const deleteProfilePicture = (filePath) => {
    if (filePath && filePath.startsWith('/uploads/')) {
        const fullPath = path.join(__dirname, filePath);
        fs.unlink(fullPath, (err) => {
            if (err) console.error(`Failed to delete old file: ${fullPath}`, err);
            else console.log(`🗑️ Successfully deleted old profile picture: ${fullPath}`);
        });
    }
};

/**
 * Sends the generated OTP via email with a responsive template.
 */
async function sendOtpEmail(recipientEmail, otp) {
    const mailOptions = {
        from: `Sunflower Union Security <${process.env.EMAIL_USER}>`,
        to: recipientEmail,
        subject: 'Sunflower Union: Your Secure Login Code',
        html: `
            <!-- Main Responsive Container -->
            <div style="
                font-family: Arial, sans-serif; 
                padding: 15px; 
                border: 1px solid #ddd; 
                max-width: 450px; 
                width: 90%; 
                margin: auto; 
                border-radius: 6px; 
                border-top: 4px solid #ffcb05; 
                box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            ">
                <div style="text-align: center; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #eee;">
                    <!-- Sunflower Bank Logo -->
                    <img src="https://i.imgur.com/NQxhjxt.png" alt="Sunflower Bank Logo" style="width: 150px; height: auto;">
                </div>
                
                <h1 style="color: #0076a3; font-size: 22px; text-align: center; margin-top: 0; margin-bottom: 15px;">
                    One-Time Verification Code
                </h1>
                
                <p style="font-size: 15px; color: #333; text-align: center; line-height: 1.5;">
                    Use the code below to complete your login securely:
                </p>
                
                <!-- OTP Code Block -->
                <div style="
                    background-color: #0076a3; 
                    padding: 15px 10px; 
                    border-radius: 6px; 
                    text-align: center; 
                    margin: 25px 0;
                ">
                    <h2 style="
                        font-size: 32px; 
                        color: white; 
                        font-weight: bold; 
                        margin: 0; 
                        letter-spacing: 4px;
                    ">${otp}</h2>
                </div>
                
                <p style="margin-top: 20px; font-size: 13px; color: #777; line-height: 1.4;">
                    This code is valid for **10 minutes**. For your security, **do not share this code** with anyone, including bank employees.
                </p>
                
                <p style="font-size: 11px; color: #aaa; margin-top: 25px; text-align: center; border-top: 1px solid #eee; padding-top: 10px;">
                    If you did not request this login, please contact support immediately.
                </p>
            </div>
        `,
    };

    try {
        // FIX: Send the actual email
        const info = await transporter.sendMail(mailOptions);
        console.log(`✅ Real OTP Email Sent: %s to ${recipientEmail}`, info.messageId);
        
        // REMOVED: console.log(`Email sent successfully (simulated) to ${recipientEmail}`);
    } catch (error) {
        console.error(`❌ ERROR: Failed to send OTP email to ${recipientEmail}. Check NodeMailer/SMTP config.`, error);
        // Throw an error to be caught by the main login route, preventing login continuation
        throw new Error('Failed to send verification code. Please contact support.');
    }
}
// Helper function to mask the email address for security display (e.g., m***e@gmail.com)
function maskEmail(email) {
    if (!email) return 'N/A';
    const parts = email.split('@');
    if (parts.length !== 2) return email;

    const localPart = parts[0];
    const domainPart = parts[1];

    if (localPart.length <= 3) return localPart[0] + '***@' + domainPart;
    
    // Mask the local part: first char + *** + last char
    const maskedLocal = localPart.substring(0, 1) + '***' + localPart.substring(localPart.length - 1);
    
    return maskedLocal + '@' + domainPart;
}

/**
 * Generates a random 6-digit OTP, hashes it, saves it to the DB with expiry, and sends the email.
 */
async function generateAndSendOtp(user) {
    // Generate a random 6-digit number
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiration = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes

    // 1. Hash the OTP before saving (ALWAYS hash sensitive data)
    const salt = await bcrypt.genSalt(10);
    const hashedOtp = await bcrypt.hash(otp, salt);

    // 2. Save the hashed OTP and expiry to the user document
    // NOTE: Your User Model must have 'otpHash' (String) and 'otpExpiration' (Date) fields
    user.otpHash = hashedOtp;
    user.otpExpiration = otpExpiration;
    
    // CRITICAL FIX: Persist the changes to the database immediately.
    // This is the step that resolves the "No pending OTP" error.
    await user.save(); 
    console.log(`✅ Real OTP Database Saved: OTP hash and 10-minute expiry stored for ${user.userIdName}.`);


    // 3. Send the PLAIN TEXT OTP via email
    // You should ensure your 'sendOtpEmail' function is properly implemented.
    await sendOtpEmail(user.email, otp);
    console.log(`✅ OTP Email Sent to ${user.email}.`);


    return true; // Indicates success
}

// -----------------------------
// --- JWT AUTHENTICATION MIDDLEWARE ---
// -----------------------------

/**
 * Middleware to verify a JWT from the 'Authorization' header.
 * Attaches the decoded admin payload to req.admin if valid.
 */
const verifyAdminToken = (req, res, next) => {
    // 1. Check for the token in the header
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        console.log('❌ Auth Failed: Missing Authorization header.');
        return res.status(401).json({ success: false, message: 'Access Denied. No token provided.' });
    }

    // Expected format: "Bearer [TOKEN]"
    const token = authHeader.split(' ')[1]; 
    if (!token) {
        console.log('❌ Auth Failed: Token format invalid.');
        return res.status(401).json({ success: false, message: 'Access Denied. Invalid token format.' });
    }

    // 2. Verify the token using the secret
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Attach the decoded admin payload to the request for use in routes
        req.admin = decoded; 
        // NOTE: The previous version also checked for req.admin.id but the JWT payload
        // should contain the id, so we ensure it's available for card generation
        req.admin.id = decoded.id || decoded._id; 
        console.log(`✅ Token Verified for Admin: ${req.admin.email}`);
        next(); // Proceed to the next middleware/route handler
    } catch (ex) {
        // This catches errors like 'invalid signature', 'jwt malformed', and 'jwt expired'
        console.log('❌ Auth Failed: JWT verification failed.', ex.message);
        // Explicitly set 401 for unauthorized access
        return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
    }
};

/**
 * Generates a JSON Web Token (JWT) for a successful user login.
 * Uses the globally available JWT_SECRET.
 * @param {Object} user - The Mongoose user document containing _id, userIdName, and role.
 * @returns {string} The signed JWT token.
 */
function generateClientToken(user) {
    // 1. Define the payload (claims) - include only necessary, non-sensitive data
    const payload = {
        userId: user._id, // MongoDB object ID
        userIdName: user.userIdName,
        role: user.role,
        fullName: user.fullName 
    };

    // 2. Sign the token
    const token = jwt.sign(
        payload, 
        JWT_SECRET, // Your secret key (now globally available)
        { expiresIn: '1d' } // Token expires in 24 hours
    );

    return token;
}

/**
 * Middleware to verify a JWT from the 'Authorization' header for a CLIENT.
 * Uses the globally available JWT_SECRET.
 */
const verifyClientToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, message: 'Access Denied. No token provided.' });
    }

    const token = authHeader.split(' ')[1]; 
    if (!token) {
        return res.status(401).json({ success: false, message: 'Access Denied. Invalid token format.' });
    }

    try {
        // Use globally available jwt object and JWT_SECRET
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Assuming role is stored as 'User'
        if (decoded.role !== 'User') { 
             return res.status(403).json({ success: false, message: 'Forbidden. Admin token cannot access client routes.' });
        }
        
        // 🚀 CRITICAL FIX: Explicitly assign the properties.
        // The transfer routes demand req.user.id. We use fallback to cover common keys.
        req.user = {
            // Check for the ID in common keys: 'id', '_id', or 'userId'
            id: decoded.id || decoded._id || decoded.userId, 
            userIdName: decoded.userIdName || decoded.username, // Use username if userIdName is missing
            role: decoded.role
        };
        
        // Update the log to confirm the ID we are setting
        console.log(`✅ Client Token Verified for User: ${req.user.userIdName} (ID: ${req.user.id})`);
        next();
    } catch (ex) {
        console.log('❌ Client Auth Failed: JWT verification failed.', ex.message);
        return res.status(401).json({ success: false, message: 'Invalid or expired client token.' });
    }
};


// Generates a random 6-digit OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

/**
 * Simulates sending the OTP to the user's registered email.
 * In a real app, this would use a service like SendGrid, Nodemailer, etc.
 * @param {string} email - The user's email address (simulated as userIdName@sunflowerbank.com)
 * @param {string} otp - The generated OTP code
 */
function sendOTPEmail(email, otp) {
    console.log(`\n📧 SIMULATED EMAIL SEND:`);
    console.log(`   TO: ${email}`);
    console.log(`   SUBJECT: Your One-Time Password (OTP)`);
    console.log(`   BODY: Your security code is ${otp}. It expires in 5 minutes.`);
    console.log('------------------------------------------');
    // NOTE: For a real application, implement actual email sending here.
}
// ------------------------------------------------------------------------------------------------

// ----------------------------------------------------------------------------------
// --- API ROUTES ---
// ----------------------------------------------------------------------------------


// Helper to format currency consistently for the email content
const formatCurrency = (amount, currencyCode = 'USD') => {
    try {
        const numberAmount = typeof amount === 'string' ? parseFloat(amount) : amount;
        if (isNaN(numberAmount)) return `${currencyCode} 0.00`;
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: currencyCode,
        }).format(numberAmount);
    } catch (e) {
        return `${currencyCode} ${amount.toFixed(2)}`;
    }
};

// 2. Email Sending Function (Enhanced with Logo and Styling)
async function sendTransferNotification(userEmail, transactionDetails) {
    console.log(`\nAttempting to send notification email to: ${userEmail}`);
    
    // IMPORTANT: Assuming the 'transporter' object is defined globally 
    // using 'const transporter = nodemailer.createTransport({...});'
    if (!transporter) {
        console.error('❌ ERROR: Nodemailer transporter is not configured or is undefined.');
        return;
    }
    
    // Define the logo URL
    const LOGO_URL = "https://i.imgur.com/NQxhjxt.png";

    const mailOptions = {
        from: '"Sunflower Bank" <no-reply@sunflowerbank.com>',
        to: userEmail,
        subject: `Transaction Alert: Funds Transferred (${transactionDetails.formattedAmount})`,
        html: `
            <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; border: 1px solid #ddd; border-radius: 10px; overflow: hidden;">
                
                <div style="background-color: #aedffcff; padding: 20px; text-align: center;">
                    <img src="${LOGO_URL}" alt="Sunflower Bank Logo" style="max-height: 50px; border-radius: 5px;">
                    <h1 style="color: #0076a3; font-size: 1.5em; margin-top: 10px;">Transaction Confirmation</h1>
                </div>

                <div style="padding: 20px;">
                    <p>Dear Customer,</p>
                    <p>This confirms your recent **${transactionDetails.transferType}** transfer has been processed successfully.</p>
                    
                    <table style="width: 100%; border-collapse: collapse; margin-top: 25px; background-color: #f9f9f9; border: 1px solid #eee;">
                        <tr>
                            <td style="padding: 12px; border-bottom: 1px solid #eee; font-weight: bold; color: #0076a3;">Transaction Detail</td>
                            <td style="padding: 12px; border-bottom: 1px solid #eee; font-weight: bold; color: #0076a3; text-align: right;">Value</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px; border-bottom: 1px solid #eee;"><strong>Amount Transferred:</strong></td>
                            <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: right; color: #008000; font-weight: bold;">${transactionDetails.formattedAmount}</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px; border-bottom: 1px solid #eee;">Source Account (Last 4):</td>
                            <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: right;">${transactionDetails.sourceAccountNumber.slice(-4)}</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px; border-bottom: 1px solid #eee;">Recipient:</td>
                            <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: right;">${transactionDetails.destinationName}</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px; border-bottom: 1px solid #eee;">Reference ID:</td>
                            <td style="padding: 12px; border-bottom: 1px solid #eee; text-align: right;">${transactionDetails.referenceId}</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px;"><strong>New Source Balance:</strong></td>
                            <td style="padding: 12px; text-align: right; font-weight: bold;">${transactionDetails.newBalance}</td>
                        </tr>
                    </table>

                    <p style="margin-top: 30px;">Thank you for banking with Sunflower Bank. If you have any questions, please contact our support team.</p>
                </div>
                
                <div style="background-color: #f0f0f0; padding: 15px; text-align: center; font-size: 0.8em; color: #666;">
                    This is an automated notification. Please do not reply to this email.
                </div>
            </div>
        `,
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log(`✅ Email notification successfully sent to ${userEmail}. Message ID: ${info.messageId}`);
    } catch (error) {
        console.error(`❌ ERROR: Failed to send transfer confirmation email to ${userEmail}.`, error);
        // Important: Do not return an error status here; the transaction is already committed.
    }
}

// POST /api/users - Register New User (Client)
app.post('/api/users', upload.single('profilePicture'), async (req, res) => {
    // Destructure all expected fields for clarity and consistent validation
    const { 
        userIdName, userPassword, fullName, email, dob, gender, 
        address, occupation, transferPin, currency 
    } = req.body;
    
    const profileFile = req.file; 
    
    console.log(`\n--- Received Data for New User (${fullName}) ---`);
    console.log('User ID Name:', userIdName, 'Email:', email);

    // --- SERVER-SIDE VALIDATION ---
    const requiredFields = { userIdName, userPassword, fullName, email, dob, address, occupation, transferPin, currency };
    
    for (const key in requiredFields) {
        if (!requiredFields[key]) {
            if (profileFile) fs.unlinkSync(profileFile.path); 
            return res.status(400).json({ success: false, message: `Missing required field: ${key}` });
        }
    }
    
    if (userIdName.length < 5) {
        if (profileFile) fs.unlinkSync(profileFile.path); 
        return res.status(400).json({ success: false, message: 'User ID Name must be at least 5 characters long.' });
    }
    
    if (userPassword.length < 8) {
        if (profileFile) fs.unlinkSync(profileFile.path); 
        return res.status(400).json({ success: false, message: 'User Password must be at least 8 characters long.' });
    }

    if (!/^\d{4}$/.test(transferPin)) {
        if (profileFile) fs.unlinkSync(profileFile.path);
        return res.status(400).json({ success: false, message: 'Transfer PIN must be exactly 4 numeric digits.' });
    }
    
    // Basic Email format validation 
    if (!/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(email)) {
        if (profileFile) fs.unlinkSync(profileFile.path);
        return res.status(400).json({ success: false, message: 'Invalid email address format.' });
    }

    // --- DATA PROCESSING & REAL MONGO DB SAVE ---
    try {
        // 1. Generate secure hashes using bcrypt
        const passwordHash = await bcrypt.hash(userPassword, SALT_ROUNDS);
        const transferPinHash = await bcrypt.hash(transferPin, SALT_ROUNDS);
        
        // 2. Generate two unique accounts (Checking and Savings)
        console.log('Generating unique Checking Account...');
        const checkingAccount = await generateUniqueAccountDetails(User, currency, 'Checking', 0.00); 
        
        console.log('Generating unique Savings Account...');
        const savingsAccount = await generateUniqueAccountDetails(User, currency, 'Savings', 0.00); 

        // 3. Create the new User document object
        const newUser = new User({
            userIdName: userIdName, 
            email: email, // <-- ADDED EMAIL HERE
            passwordHash: passwordHash, 
            transferPinHash: transferPinHash,
            
            fullName: fullName,
            dob: new Date(dob), // Ensure it's stored as a Date
            gender: gender,
            address: address,
            occupation: occupation,
            
            profilePicturePath: profileFile ? `/uploads/${profileFile.filename}` : null,
            accounts: [checkingAccount, savingsAccount],
            currency: currency, 
            role: 'User' // Explicitly set role
        });
        
        // 🔑 VERIFICATION LOG: Check that Mongoose has applied the default nulls for 2FA fields
        console.log('New User Object before Save (Check for otpSecret/otpExpiry):', {
            userIdName: newUser.userIdName,
            email: newUser.email,
            otpSecret: newUser.otpSecret, 
            otpExpiry: newUser.otpExpiry, 
            role: newUser.role 
        });


        // 4. Save to MongoDB 
        const savedUser = await newUser.save();
        
        console.log('\n✅ User Successfully Created & Stored (MongoDB Save)');
        console.log('New User ID Name:', savedUser.userIdName); 
        console.log(`Accounts Created: Checking (${checkingAccount.accountNumber}) and Savings (${savingsAccount.accountNumber})`);
        console.log('------------------------------------------------------------');
        
        // 5. Generate JWT for immediate login
        const token = jwt.sign(
            { id: savedUser._id, role: savedUser.role, userIdName: savedUser.userIdName }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );


        // 6. Send Success Response to Client
        res.status(201).json({ 
            success: true, 
            message: 'User account created and activated successfully.',
            userId: savedUser._id,
            accounts: savedUser.accounts,
            token // Include token for auto-login after successful registration
        });

    } catch (dbError) {
        // Handle file cleanup
        if (profileFile) fs.unlinkSync(profileFile.path); 
        
        console.error('MongoDB Save Error (User):', dbError);
        
        if (dbError.code === 11000) {
            const key = Object.keys(dbError.keyValue)[0];
            const value = dbError.keyValue[key];
            
            let msg = 'Database conflict occurred. Please retry.';
            if (key === 'userIdName') {
                // --- FIX: Explicitly check for 'userIdName' duplication
                msg = `The User ID Name '${value}' is already taken. Please choose a different one.`;
            } else if (key === 'email') { 
                // --- FIX: Explicitly check for 'email' duplication
                msg = `The email address '${value}' is already registered to an account.`;
            } else {
                 msg = 'A unique constraint was violated (e.g., account number collision). Please retry the request.';
            }

            return res.status(409).json({
                success: false,
                message: msg
            });
        }
        
        // Handle Mongoose validation error (e.g., required fields, email format)
        if (dbError.name === 'ValidationError') {
             return res.status(400).json({ success: false, message: `Validation failed: ${dbError.message}` });
        }

        // Handle the error thrown by generateUniqueAccountDetails if max attempts were reached
        if (dbError.message.includes('unique bank account number')) {
            return res.status(500).json({ 
                success: false, 
                message: 'Internal Error: Could not generate a unique account number after multiple attempts. Please try again later.' 
            });
        }
        
        return res.status(500).json({ 
            success: false, 
            message: 'Database error during account creation. See server console.' 
        });
    }
});

// --------------------------------------------------
// --- API for VIEW ALL USERS (view-user-account) ---
// --------------------------------------------------
// 🚨 PROTECTED ROUTE
app.get('/api/users', verifyAdminToken, async (req, res) => {
    console.log('\n--- Received Request to View All Users ---');
    try {
        // Fetch all user documents, excluding sensitive fields (including new 2FA fields)
        const users = await User.find().select('-passwordHash -transferPinHash -otpSecret -otpExpiry -__v');
        
        console.log(`✅ Fetched ${users.length} users successfully.`);
        res.status(200).json(users);

    } catch (error) {
        console.error('Error fetching all users:', error);
        res.status(500).json({ success: false, message: 'Failed to retrieve users from the database.' });
    }
});

// --- API for VIEW SINGLE USER (FIXED for Manage Funds UI) ---
// 🚨 PROTECTED ROUTE
app.get('/api/users/:id', verifyAdminToken, async (req, res) => {
    const { id } = req.params;
    console.log(`\n--- Received GET Request for User ID: ${id} (FIXED) ---`);

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: 'Invalid user ID format.' });
    }

    try {
        // Exclude all sensitive fields, including the new 2FA fields
        const user = await User.findById(id).select('-passwordHash -transferPinHash -otpSecret -otpExpiry -__v');

        if (!user) {
            console.log(`❌ User ID ${id} not found.`);
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        
        // 🔑 FIX: Normalize accounts from Array to Object for easy frontend access
       const normalizedAccounts = user.accounts.reduce((acc, account) => {
    // This loops through the database array and creates the object structure the frontend needs
    acc[account.accountType.toLowerCase()] = {
        number: account.accountNumber,
        balance: account.balance
    };
    return acc;
}, { checking: null, savings: null });
        // Create the final response object, combining all user fields with the new account structure
        const responseData = {
            // Get all standard user fields
            ...user.toObject(),
            
            // Format DOB for the frontend input (if needed)
            dob: user.dob ? user.dob.toISOString().split('T')[0] : '', 

            // Overwrite the accounts array with the normalized object structure
            accounts: normalizedAccounts 
        };
        
        delete responseData._id; // Clean up redundant field

        console.log(`✅ User details fetched and normalized successfully for ${user.fullName}.`);
        
        // Return the clean, normalized object
        res.status(200).json(responseData);

    } catch (error) {
        console.error(`Error fetching user ${id}:`, error);
        res.status(500).json({ success: false, message: 'Server error while retrieving user data.' });
    }
});

// --- API for EDIT USER (edit-user-account & admin-message submission) ---
// 🚨 PROTECTED ROUTE - CORRECTED LOGIC FOR ANNOUNCEMENT AND ISSUE MESSAGES
app.put('/api/users/:id', verifyAdminToken, upload.single('profilePicture'), async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;
    const profileFile = req.file;

    console.log(`\n--- Received PUT Request for User ID: ${id} ---`);
    console.log('Update Data Keys:', Object.keys(updateData));

    if (!mongoose.Types.ObjectId.isValid(id)) {
        if (profileFile) fs.unlinkSync(profileFile.path);
        return res.status(400).json({ success: false, message: 'Invalid user ID format.' });
    }

    try {
        const user = await User.findById(id);
        if (!user) {
            if (profileFile) fs.unlinkSync(profileFile.path);
            return res.status(404).json({ success: false, message: 'User not found for update.' });
        }

        let changes = {};

        // Helper function to process and validate message updates (omitted for brevity, assume correct)
        const handleMessageUpdate = (messageKey, messageObj) => {
            // ... (Existing implementation remains unchanged) ...
             if (messageObj) {
                // Ensure payload contains the expected structure
                if (typeof messageObj.isActive === 'boolean' && typeof messageObj.messageContent === 'string') {
                    
                    // Server-Side Validation: Require content if message is active
                    if (messageObj.isActive && messageObj.messageContent.trim().length < 5) {
                        // Throw error to be caught by the outer try-catch block
                        throw new Error(`${messageKey} content must be at least 5 characters long if active.`);
                    }

                    changes[messageKey] = {
                        isActive: messageObj.isActive,
                        // Clear content if inactive
                        messageContent: messageObj.isActive ? messageObj.messageContent.trim() : "",
                        lastUpdatedByAdmin: req.admin.id,
                        lastUpdatedAt: new Date()
                    };
                    console.log(`✅ ${messageKey} config updated by Admin ${req.admin.id}. Active: ${messageObj.isActive}`);
                } else {
                    console.warn(`⚠️ Received malformed ${messageKey} payload. Skipping update for this field.`);
                }
            }
        };

        // 1. Handle Password update (Must be hashed)
        if (updateData.userPassword) {
            if (updateData.userPassword.length < 8) {
                if (profileFile) fs.unlinkSync(profileFile.path); 
                return res.status(400).json({ success: false, message: 'New Password must be at least 8 characters long.' });
            }
            changes.passwordHash = await bcrypt.hash(updateData.userPassword, SALT_ROUNDS);
            console.log('✅ Password hash updated.');
        }

        // 2. Handle Transfer PIN update (Must be 4 digits and hashed)
        if (updateData.transferPin) {
            if (!/^\d{4}$/.test(updateData.transferPin)) {
                if (profileFile) fs.unlinkSync(profileFile.path);
                return res.status(400).json({ success: false, message: 'Transfer PIN must be exactly 4 numeric digits.' });
            }
            changes.transferPinHash = await bcrypt.hash(updateData.transferPin, SALT_ROUNDS);
            console.log('✅ Transfer PIN hash updated.');
        }

        // 3. Handle Profile Picture update
        if (profileFile) {
            // Only delete if a previous path exists
            if (user.profilePicturePath) deleteProfilePicture(user.profilePicturePath); 
            changes.profilePicturePath = `/uploads/${profileFile.filename}`;
            console.log(`✅ Profile picture uploaded: ${changes.profilePicturePath}`);
        }

        // 4. Handle Currency/Account Details update (omitted for brevity, assume correct)
        if (updateData.currency && updateData.currency !== user.currency) {
            console.log(`🔄 Currency changed from ${user.currency} to ${updateData.currency}. Regenerating account details...`);
            
            // Regenerate both Checking and Savings accounts, preserving current balance
            const newChecking = generateAccountDetails(updateData.currency, 'Checking', user.accounts.find(a => a.accountType === 'Checking')?.balance || 0.00);
            const newSavings = generateAccountDetails(updateData.currency, 'Savings', user.accounts.find(a => a.accountType === 'Savings')?.balance || 0.00);

            changes.currency = updateData.currency;
            changes.accounts = [newChecking, newSavings];
            console.log(`✅ Account details updated for new currency: ${updateData.currency}`);
        } else if (updateData.currency && updateData.currency === user.currency) {
            changes.currency = updateData.currency;
        }
        
        // 5. Handle Conditional Message Configuration (New Logic) (omitted for brevity, assume correct)
        handleMessageUpdate('announcementMessage', updateData.announcementMessage);
        handleMessageUpdate('issueMessage', updateData.issueMessage);
        handleMessageUpdate('transferMessage', updateData.transferMessage);
        
        // ----------------------------------------------------------------
        // 6. Handle other general fields, INCLUDING EMAIL 🔑
        // ----------------------------------------------------------------
        const allowedFields = ['fullName', 'dob', 'gender', 'address', 'occupation', 'status', 'userIdName', 'email'];
        allowedFields.forEach(key => {
            if (updateData[key] !== undefined && changes[key] === undefined) { 
                
                // Extra validation for email
                if (key === 'email') {
                    if (!/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(updateData.email)) {
                        throw new Error('Invalid email address format.');
                    }
                }
                
                changes[key] = updateData[key];
            }
        });
        
        if (Object.keys(changes).length === 0) {
            if (profileFile) fs.unlinkSync(profileFile.path);
            return res.status(200).json({ success: true, message: 'No substantial changes submitted.' });
        }


        // 7. Perform the MongoDB update
        const updatedUser = await User.findByIdAndUpdate(id, { $set: changes }, { new: true, runValidators: true }).select('-passwordHash -transferPinHash -__v');
        
        if (!updatedUser) {
            if (profileFile) fs.unlinkSync(profileFile.path);
            return res.status(500).json({ success: false, message: 'Update failed, user not found after initial check.' });
        }

        console.log(`✅ User ${id} updated successfully.`);
        res.status(200).json({ 
            success: true, 
            message: `User ${updatedUser.fullName} updated successfully.`,
            user: updatedUser 
        });

    } catch (dbError) {
        // Handle custom validation error from message update helper & email validation
        if (dbError.message.includes('content must be at least 5 characters long') || 
            dbError.message.includes('Invalid email address format.')) {
            if (profileFile) fs.unlinkSync(profileFile.path);
            return res.status(400).json({ success: false, message: dbError.message });
        }

        console.error('MongoDB Update Error (User):', dbError);
        if (profileFile) fs.unlinkSync(profileFile.path); // Clean up file on DB error
        
        if (dbError.code === 11000) {
            const key = Object.keys(dbError.keyValue)[0];
            const value = dbError.keyValue[key];
            
            let msg = 'Database conflict occurred. Please retry.';
            
            // --- FIX: Explicitly check for 'userIdName' and 'email' duplication on update
            if (key === 'userIdName') {
                msg = `The User ID Name '${value}' is already taken by another user.`;
            } else if (key === 'email') {
                msg = `The email address '${value}' is already registered to another account.`;
            }

            return res.status(409).json({ success: false, message: msg });
        }

        // Handle Mongoose validation error (e.g., required fields, type mismatch)
        if (dbError.name === 'ValidationError') {
            return res.status(400).json({ success: false, message: `Validation failed: ${dbError.message}` });
        }

        res.status(500).json({ success: false, message: 'Server error during user update.' });
    }
});

/**
 * Sends a notification email to the user about their transaction status change.
 * @param {string} userEmail - The user's email address.
 * @param {string} userName - The user's full name.
 * @param {string} transactionId - The ID of the transaction.
 * @param {string} newStatus - The new status (e.g., 'Approved', 'Rejected', 'Processing').
 * @param {string} [notificationContext] - The specific context for the email (e.g., 'your transaction (debit leg)').
 */
async function sendStatusUpdateEmail(userEmail, userName, transactionId, newStatus, notificationContext) {
    // NOTE: This assumes 'transporter' (defined with process.env variables) is accessible in this scope.
    // If this file is imported, 'transporter' must be imported or passed in. Assuming it's a global/accessible dependency here.
    const LOGO_URL = 'https://i.imgur.com/NQxhjxt.png';
    const BANK_COLOR = '#0076a3'; // Primary bank color
    
    // --- 1. Dynamic Content Mapping based on newStatus ---
    let contextMessage;
    let statusColor;
    let statusEmoji;
    let accentBackgroundColor;

    // Use a switch or if/else to determine dynamic content
    switch (newStatus.toUpperCase()) {
        case 'APPROVED':
            contextMessage = 'has been **successfully approved**. Your funds are being processed.';
            statusColor = '#28a745'; // Green for success
            statusEmoji = '✅';
            accentBackgroundColor = '#e6ffed';
            break;
        case 'REJECTED':
        case 'FAILED':
        case 'DECLINED':
            contextMessage = 'has unfortunately been **rejected**. Please check your designated agent.';
            statusColor = '#dc3545'; // Red for failure
            statusEmoji = '❌';
            accentBackgroundColor = '#fff0f3';
            break;
        case 'PROCESSING':
            contextMessage = 'is now **processing**. We will notify you upon final completion.';
            statusColor = '#ffc107'; // Yellow/Orange for pending
            statusEmoji = '⏳';
            accentBackgroundColor = '#fffceb';
            break;
        case 'REFUNDED':
            contextMessage = 'has been **refunded**. The funds have been returned to your account.';
            statusColor = '#0076a3'; // Blue for Refund/Reversal
            statusEmoji = '↩️';
            accentBackgroundColor = '#e6f7ff';
            break;
        default:
            contextMessage = 'has been updated. Check your account for more details.';
            statusColor = BANK_COLOR; // Default bank color
            statusEmoji = '🔔';
            accentBackgroundColor = '#e6f7ff';
            break;
    }
    
    // New variable to embed the specific context for the user 
    const userSpecificContext = notificationContext ? `for ${notificationContext}` : '';
    
    // -----------------------------------------------------

    const subject = `${statusEmoji} Update: Your Transaction Status is Now ${newStatus}`;
    
    // --- Professional HTML Template with Inline CSS ---
    // (Template is kept identical to the provided block)
    const htmlBody = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${subject}</title>
            <style>
                body, table, td, a { -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
                table, td { mso-table-lspace: 0pt; mso-table-rspace: 0pt; }
                img { -ms-interpolation-mode: bicubic; }
                a[x-apple-data-detectors] { color: inherit !important; text-decoration: none !important; font-size: inherit !important; font-family: inherit !important; font-weight: inherit !important; line-height: inherit !important; }
            </style>
        </head>
        <body style="margin: 0; padding: 0; background-color: #f4f4f4; font-family: Arial, sans-serif;">

            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="table-layout: fixed;">
                <tr>
                    <td align="center" style="padding: 20px 0;">
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                            
                            <tr>
                                <td align="center" style="padding: 20px 20px 10px 20px; background-color: ${BANK_COLOR}; border-top-left-radius: 8px; border-top-right-radius: 8px;">
                                    <img src="${LOGO_URL}" alt="Bank Logo" width="150" style="display: block; border: 0; max-width: 150px;">
                                </td>
                            </tr>
                            
                            <tr>
                                <td style="padding: 25px 30px 40px 30px; color: #333333;">
                                    <h1 style="font-size: 24px; color: ${BANK_COLOR}; margin: 0 0 20px 0;">Transaction Status Updated</h1>
                                    
                                    <p style="margin: 0 0 15px 0; font-size: 16px; line-height: 1.6;">Dear ${userName},</p>
                                    
                                    <p style="margin: 0 0 20px 0; font-size: 16px; line-height: 1.6;">
                                        This is an automated notification ${userSpecificContext}. Your recent transaction 
                                        (<span style="font-family: monospace; font-size: 14px; background-color: #f0f0f0; padding: 2px 5px; border-radius: 4px; display: inline-block;">ID: ${transactionId.substring(0, 8)}...</span>) 
                                        ${contextMessage.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')}
                                    </p>
                                    
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom: 30px; border-collapse: separate !important;">
                                        <tr>
                                            <td style="background-color: ${accentBackgroundColor}; border: 1px solid ${statusColor}44; padding: 15px; border-radius: 6px; text-align: center;">
                                                <p style="font-size: 18px; color: ${BANK_COLOR}; margin: 0 0 5px 0; font-weight: bold;">Current Status:</p>
                                                <p style="font-size: 28px; color: ${statusColor}; margin: 0; font-weight: 900; line-height: 1;">${newStatus} ${statusEmoji}</p>
                                            </td>
                                        </tr>
                                    </table>

                                    <p style="margin: 0 0 30px 0; font-size: 16px; line-height: 1.6; text-align: center;">
                                        <a href="[LINK_TO_DASHBOARD]" target="_blank" style="text-decoration: none; display: inline-block; padding: 12px 25px; font-size: 16px; color: #ffffff; background-color: ${BANK_COLOR}; border-radius: 4px; font-weight: bold;">
                                            View Transaction History
                                        </a>
                                    </p>
                                    
                                    <p style="margin: 0; font-size: 16px; line-height: 1.6;">Thank you for banking with us,<br><strong>Your Bank Team</strong></p>
                                </td>
                            </tr>

                            <tr>
                                <td align="center" style="padding: 20px 30px; font-size: 12px; color: #999999; border-top: 1px solid #eeeeee;">
                                    <p style="margin: 0;">This email was sent automatically. Please do not reply.</p>
                                </td>
                            </tr>

                        </table>
                    </td>
                </tr>
            </table>

        </body>
        </html>
    `;

    // -----------------------------------------------------
    // 🛑 LIVE EMAIL SENDING LOGIC
    // -----------------------------------------------------
    try {
        const info = await transporter.sendMail({
            from: `"Sunflower Union Security" <${process.env.EMAIL_USER}>`, // Sender email from env
            to: userEmail,
            subject: subject,
            html: htmlBody,
        });

        console.log(`\n📧 LIVE EMAIL SENT:`);
        console.log(`   To: ${userEmail}`);
        console.log(`   Subject: ${subject}`);
        console.log(`   Message ID: ${info.messageId}`);
        
    } catch (error) {
        // This is the error handler for the live email attempt
        console.error(`\n❌ CRITICAL ERROR: Failed to send LIVE email to ${userEmail}.`);
        console.error(`   Error details:`, error.message);
    }
    console.log('------------------------------------------');
}

module.exports = { sendStatusUpdateEmail };


// GET endpoint to fetch all transactions for a specific user (Admin Protected)
// URL structure from frontend: /api/transactions/user/:userId
app.get('/api/transactions/user/:userId', verifyAdminToken, async (req, res) => {
    const { userId } = req.params;

    console.log(`\n--- Received Fetch Transactions Request for User ID: ${userId} ---`);

    // --- 1. Basic Validation ---
    if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ success: false, message: 'Invalid user ID format.' });
    }

    try {
        // --- 2. Fetch User to ensure existence (optional, but good practice) ---
        const userExists = await User.exists({ _id: userId });
        if (!userExists) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        
        // --- 3. Fetch all Transactions ---
        const transactions = await Transaction.find({ userId: userId })
            // Exclude __v, but include all fields required by the frontend
            .select('-__v') 
            .sort({ timestamp: -1 }); // Sort by newest first

        // Note: The frontend expects fields like _id, timestamp, accountId, description, amount, status, currency.
        // We'll trust the Transaction model includes these.

        console.log(`✅ Fetched ${transactions.length} transactions for user ${userId}.`);

        // --- 4. Success Response ---
        res.status(200).json({
            success: true,
            transactions: transactions,
            count: transactions.length
        });

    } catch (error) {
        console.error('Database/Fetch Error (Admin Transactions):', error);
        res.status(500).json({ success: false, message: 'Server error while retrieving user transactions.' });
    }
});

// =======================================================================
// ⭐ UTILITY FUNCTIONS (Defined once and used globally) ⭐
// =======================================================================

/**
 * Placeholder for the non-critical audit logging function.
 * In a production app, this would insert a record into a dedicated log table.
 */
async function logStatusChange(txId, oldStatus, newStatus, adminId) {
    // NOTE: Replace this console.log with your actual database logging logic.
    console.log(`[AUDIT LOG] TX ${txId} status changed from ${oldStatus} to ${newStatus} by Admin ${adminId}`);
    // await AuditLog.create({ transaction: txId, oldStatus, newStatus, admin: adminId });
    return true;
}

// -----------------------------------------------------------------------
// THE DUPLICATE/MOCK sendStatusUpdateEmail FUNCTION WAS DELETED HERE.
// THE LIVE FUNCTION AT THE TOP IS NOW CORRECTLY ACCESSIBLE.
// -----------------------------------------------------------------------


// =======================================================================
// ⭐ TRANSACTION STATUS UPDATE ROUTE (The original code) ⭐
// =======================================================================

app.put('/api/transactions/:transactionId/status', verifyAdminToken, async (req, res) => {
    const { transactionId } = req.params;
    const { newStatus } = req.body;
    const adminId = req.admin.id; // Get admin ID from JWT payload

    console.log(`\n--- Received Transaction Status Update Request ---`);
    console.log(`TX ID: ${transactionId}, New Status: ${newStatus}, Admin: ${adminId}`);

    // --- 1. Basic Validation ---
    if (!mongoose.Types.ObjectId.isValid(transactionId)) {
        return res.status(400).json({ success: false, message: 'Invalid transaction ID format.' });
    }
    if (!newStatus) {
        return res.status(400).json({ success: false, message: 'Missing required field: newStatus.' });
    }

    const allowedStatuses = ['Pending', 'Processing', 'Approved', 'Successful', 'Delivered', 'Refunded', 'Failed', 'Declined'];
    const reversalStatuses = ['Refunded', 'Failed', 'Declined'];
    const completionStatus = 'Successful';

    if (!allowedStatuses.includes(newStatus)) {
        return res.status(400).json({ success: false, message: `Invalid status value: ${newStatus}.` });
    }

    // --- Global variables captured for post-commit actions ---
    let transactionUserId = null; 
    let transactionOldStatus = null; 
    let userToCredit = null; // Recipient user object (if internal transfer)
    let updatedTransaction = null; 
    let transactionIsInternal = false;

    // --- 2. Start Mongoose Session (for atomicity) ---
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        // --- 3. Fetch Original Transaction (the DEBIT leg) ---
        const transaction = await Transaction.findById(transactionId).session(session);

        if (!transaction) {
            await session.abortTransaction();
            console.log(`❌ Status Update Failed: Transaction ID ${transactionId} not found.`);
            return res.status(404).json({ success: false, message: 'Transaction not found.' });
        }

        const currentStatus = transaction.status;
        transactionOldStatus = currentStatus; 
        transactionUserId = transaction.userId; 
        transactionIsInternal = transaction.isInternal; // Capture isInternal state

        if (currentStatus === newStatus) {
             await session.commitTransaction();
             return res.status(200).json({
                 success: true,
                 message: `Transaction status is already ${newStatus}. No change needed.`,
                 transactionId: transaction._id,
                 newStatus: newStatus
             });
        }

        const { accountNumber, amount, destinationAccountNumber, referenceId } = transaction; 
        let accountUpdate = 0;
        
        // --- 4. Determine Financial Action based on Status Change ---
        
        // A. Handle REVERSAL 
        if (reversalStatuses.includes(newStatus)) {
             // Only reverse if the amount was a debit (negative) and it wasn't already completed/revers
             if (currentStatus !== completionStatus && !reversalStatuses.includes(currentStatus)) {
                 if (amount < 0) {
                     accountUpdate = Math.abs(amount); // Return debited funds
                     console.log(`🔄 Reversal detected. Adding back ${accountUpdate} to source account ${accountNumber}.`);
                 } else {
                     console.log(`⚠️ Reversal requested for a non-debit/already reversed transaction. No balance change applied.`);
                 }
             }
        } 
        
        // B. Handle SUCCESSFUL COMPLETION (The CREDIT Leg for transfers)
        else if (newStatus === completionStatus) {
            if (currentStatus === 'Processing' || currentStatus === 'Approved' || currentStatus === 'Pending') {
                if (transactionIsInternal) {
                    if (!destinationAccountNumber) {
                        throw new Error('Internal transfer lacks a destination account number. Cannot complete.');
                    }
                    
                    // 1. Find the User associated with the destination account (the recipient).
                    userToCredit = await User.findOne({ 'accounts.accountNumber': destinationAccountNumber })
                        .session(session)
                        .select('_id accounts currency email fullName') 
                        .lean(); 

                    if (!userToCredit) {
                        await session.abortTransaction();
                        console.log(`❌ Recipient user with destination account ${destinationAccountNumber} not found. TX Rolled back.`);
                        return res.status(404).json({ success: false, message: `Recipient user for destination account ${destinationAccountNumber} not found.` });
                    }
                    
                    const destinationAccount = userToCredit.accounts.find(acc => acc.accountNumber === destinationAccountNumber);

                    if (!destinationAccount) {
                        await session.abortTransaction();
                        console.log(`❌ Destination Account not found on user document. TX Rolled back.`);
                        return res.status(400).json({ success: false, message: `Destination account ${destinationAccountNumber} found, but is not active/accessible on the recipient's user document.` });
                    }
                    
                    const creditAmount = Math.abs(amount); // Amount to be credited is the positive value
                    
                    // 2. Credit the Destination Account Balance
                    await User.updateOne(
                        { _id: userToCredit._id, 'accounts.accountNumber': destinationAccountNumber },
                        { $inc: { 'accounts.$.balance': creditAmount } }, 
                        { session: session, runValidators: true }
                    );
                    
                    // 3. Create the second Transaction History Record (Credit Leg)
                    const creditReferenceId = `${referenceId}-CR`; 
                    await Transaction.create([{ 
                        userId: userToCredit._id, 
                        timestamp: new Date(), 
                        amount: creditAmount, 
                        description: `Internal Credit Ref: ${referenceId}`,
                        accountNumber: destinationAccountNumber, 
                        accountType: destinationAccount.accountType,
                        referenceId: creditReferenceId, 
                        status: 'Successful', 
                        relatedDebitRef: referenceId, 
                        isInternal: true 
                    }], { session: session });

                    console.log(`⭐ Internal Credit Leg Completed: ${creditAmount} added to ${destinationAccountNumber} (User: ${userToCredit._id}).`);
                    
                } else {
                    console.log(`⭐ External Transfer Marked Successful. Debit previously applied.`);
                }
            }
        }

        // C. Apply Account Update for Reversals (if necessary)
        if (accountUpdate !== 0) {
            const updateResult = await User.findOneAndUpdate(
                { "accounts.accountNumber": accountNumber },
                { $inc: { "accounts.$[elem].balance": accountUpdate } },
                { new: true, runValidators: true, session, arrayFilters: [{ "elem.accountNumber": accountNumber }] }
            );

            if (!updateResult) {
                await session.abortTransaction();
                return res.status(404).json({ success: false, message: `Account with number ${accountNumber} not found for reversal update.` });
            }
            console.log(`💰 Source Account ${accountNumber} balance successfully reversed by ${accountUpdate}.`);
        }

        // --- 5. Update Original Transaction Status (The Debit Leg) ---
        updatedTransaction = await Transaction.findByIdAndUpdate(
            transactionId,
            { $set: { status: newStatus, lastUpdatedByAdmin: adminId, updatedAt: new Date() } },
            { new: true, runValidators: true, session }
        ).select('_id status userId');

        if (!updatedTransaction) {
            await session.abortTransaction();
            return res.status(500).json({ success: false, message: 'Failed to update transaction status.' });
        }

        // --- 6. Commit Transaction ---
        await session.commitTransaction();
        console.log(`✅ Atomic Update Success! TX ${updatedTransaction._id} status is now ${updatedTransaction.status}.`);

        // --- 7. Final Success Response (SENT IMMEDIATELY AFTER COMMIT) ---
        res.status(200).json({
            success: true,
            message: `Transaction status successfully changed to ${updatedTransaction.status} and ${transactionIsInternal ? 'internal credit leg executed' : 'balance adjusted (if reversed)'}.`,
            transactionId: updatedTransaction._id,
            newStatus: updatedTransaction.status
        });

        // --------------------------------------------------------------------------
        // ⭐ Post-Commit Actions (Decoupled Fire-and-Forget) ⭐
        // --------------------------------------------------------------------------
        // These tasks run ASYNCHRONOUSLY but are not awaited, guaranteeing the HTTP response is sent first.
        (async () => {
            try {
                // A. Update Transaction History/Audit Log 
                await logStatusChange(transactionId, transactionOldStatus, newStatus, adminId);
            } catch (err) {
                // This catch block handles the history logging failure gracefully
                console.error("History logging failed (non-critical):", err);
            }

            try {
                // B. Send Email Notification
                
                const userIdsToNotify = [transactionUserId]; // Always notify the original user (sender)

                // If it was an internal transfer successfully completed, also notify the recipient.
                if (transactionIsInternal && newStatus === completionStatus && userToCredit) {
                    userIdsToNotify.push(userToCredit._id);
                }

                for (const userId of userIdsToNotify) {
                    const user = await User.findById(userId).select('email fullName');
                    
                    if (user && user.email) {
                        // Determine which transaction context to send (the debit leg for sender, or the credit leg for recipient)
                        const contextMessage = (userId.toString() === transactionUserId.toString()) ? 
                                                     'your transaction (debit leg)' : 
                                                     'a new credit/deposit';

                        // sendStatusUpdateEmail is now the LIVE function defined at the top.
                        await sendStatusUpdateEmail(
                            user.email,
                            user.fullName || 'Valued Customer',
                            transactionId, 
                            newStatus,
                            contextMessage // <-- Now the correct 5th argument for context
                        );
                    }
                }
            } catch (error) {
                // This catch block handles the email failure gracefully (non-critical path)
                console.error("Email sending failed (non-critical):", error);
            }
        })();

    } catch (error) {
        // --- 8. Abort Transaction on Error ---
        await session.abortTransaction();
        
        console.error('================================================================');
        console.error('❌ FATAL DATABASE/UPDATE ERROR (Transaction Rolled Back) ❌');
        console.error(`Error Details (Mongoose/MongoDB Exception):`, error);
        console.error('================================================================');
        
        // --- RESILIENT ERROR RESPONSE ---
        if (!res.headersSent) {
             res.status(500).json({ 
                 success: false, 
                 message: error.message || 'Server error during transaction status update. Operation rolled back.' 
             });
        }
    } finally {
        // Ensure session is always closed
        session.endSession();
    }
});

// ----------------------------------------------------
// --- API for DELETE USER (view-user-account) ---
// ----------------------------------------------------
// 🚨 PROTECTED ROUTE
app.delete('/api/users/:id', verifyAdminToken, async (req, res) => {
    const { id } = req.params;

    console.log(`\n--- Received DELETE Request for User ID: ${id} ---`);

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: 'Invalid user ID format.' });
    }

    try {
        // Find the user first to get the profile picture path
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found for deletion.' });
        }
        
        // Proceed with deletion
        const result = await User.deleteOne({ _id: id });

        if (result.deletedCount === 0) {
            return res.status(404).json({ success: false, message: 'User not found to delete.' });
        }
        
        // Delete the profile picture file
        deleteProfilePicture(user.profilePicturePath);

        console.log(`✅ User ${id} deleted successfully. Deleted profile picture if it existed.`);
        res.status(200).json({ success: true, message: `User ${id} and associated data deleted successfully.` });

    } catch (error) {
        console.error(`Error deleting user ${id}:`, error);
        res.status(500).json({ success: false, message: 'Server error during user deletion.' });
    }
});

// ------------------------------------
// --- API for FUND TRANSFER (Credit/Debit) ---
// ------------------------------------
// 🚨 NEW PROTECTED ROUTE for manage-user-funds.html
app.post('/api/funds/transfer', verifyAdminToken, async (req, res) => {
    // Expected body: { userId, accountNumber, type: 'credit'|'debit', amount, description, adminName }
    const { userId, accountNumber, type, amount, description } = req.body;
    // NOTE: req.admin.id and req.admin.email are assumed to be set by verifyAdminToken middleware
    const adminId = req.admin.id;
    
    console.log(`\n--- Received ${type ? type.toUpperCase() : 'FUND'} Request from Admin ${adminId} ---`);
    console.log(`Details: User ${userId}, Account ${accountNumber}, Amount ${amount}, Reason: ${description}`);

    // --- 1. Basic Validation ---
    if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ success: false, message: 'Invalid user ID format.' });
    }
    if (!accountNumber || !type || !amount || !description) {
        return res.status(400).json({ success: false, message: 'Missing required transaction fields.' });
    }
    const transactionAmount = parseFloat(amount);
    if (transactionAmount <= 0 || isNaN(transactionAmount)) {
        return res.status(400).json({ success: false, message: 'Amount must be a positive number.' });
    }
    if (type !== 'credit' && type !== 'debit') {
        return res.status(400).json({ success: false, message: 'Invalid transaction type. Must be "credit" or "debit".' });
    }

    // Use a session/transaction for atomicity
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        // --- 2. Find and Lock User/Account ---
        const user = await User.findOne(
            { _id: userId, 'accounts.accountNumber': accountNumber },
            null,
            { session: session }
        );

        if (!user) {
            await session.abortTransaction();
            console.log('❌ Transaction Failed: User or account not found.');
            return res.status(404).json({ success: false, message: 'User or target account not found.' });
        }

        const account = user.accounts.find(a => a.accountNumber === accountNumber);
        let newBalance = account.balance;
        let finalSignedAmount; // The signed amount saved in the Transaction history

        // --- 3. Perform Transaction Logic ---
        if (type === 'credit') {
            newBalance += transactionAmount;
            finalSignedAmount = transactionAmount; // Positive for credit
            console.log(`➕ Crediting ${transactionAmount.toFixed(2)} to Account ${accountNumber}.`);
        } else if (type === 'debit') {
            if (account.balance < transactionAmount) {
                await session.abortTransaction();
                console.log('❌ Transaction Failed: Insufficient funds.');
                return res.status(400).json({ success: false, message: 'Insufficient funds for this debit operation.' });
            }
            newBalance -= transactionAmount;
            finalSignedAmount = -transactionAmount; // Negative for debit
            console.log(`➖ Debiting ${transactionAmount.toFixed(2)} from Account ${accountNumber}.`);
        }

        // --- 4. Update MongoDB Document (Sub-document update) ---
        const updateResult = await User.updateOne(
            { _id: userId, 'accounts.accountNumber': accountNumber },
            { $set: { 'accounts.$.balance': newBalance } }, 
            { session: session, runValidators: true }
        );

        if (updateResult.modifiedCount === 0) {
             // Rollback transaction if any step failed
            await session.abortTransaction().catch(() => {}); 
            session.endSession();
            console.error('Database/Transaction Error: Failed to update balance.');
            return res.status(500).json({ success: false, message: 'Failed to update balance. Transaction aborted.' });
        }


        // --- 4.5. CREATE TRANSACTION HISTORY RECORD (FIXED DESCRIPTION) ---
        // This ensures only the user's description is saved, not "Admin CREDIT:"
        await Transaction.create([{
            userId: user._id,
            date: new Date(),
            amount: finalSignedAmount, // Signed amount for dashboard history
            description: description, // CORRECT: Uses only the admin's provided description
            accountNumber: account.accountNumber,
            accountType: account.accountType,
            referenceId: `ADMIN-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
            adminProcessedBy: adminId
        }], { session: session });

        await session.commitTransaction();
        session.endSession();
        
        console.log(`✅ Transaction Success! New Balance: ${newBalance.toFixed(2)} ${user.currency}`);

        // --- 5. Success Response ---
        res.status(200).json({
            success: true,
            message: `${type.toUpperCase()} successful. Transaction recorded.`,
            newBalance: newBalance,
            currency: user.currency 
        });

    } catch (error) {
        // Rollback transaction if any step failed
        await session.abortTransaction().catch(() => {}); 
        session.endSession();
        console.error('Database/Transaction Error:', error);
        res.status(500).json({ success: false, message: error.message || 'Server error during fund transfer.' });
    }
});

// ------------------------------------
// --- ADMIN REGISTRATION/LOGIN API ---
// ------------------------------------

// POST endpoint for new Admin Account creation (Does NOT require token)
// NOTE: One of the 'api/admins/register' routes was a duplicate. Keeping the first one.
app.post('/api/admins/register', async (req, res) => {
    
    const { fullName, email, password } = req.body;

    console.log(`\n--- Received Data for New Admin (${email}) ---`);

    // --- SERVER-SIDE VALIDATION ---
    if (!fullName || !email || !password) {
        return res.status(400).json({ success: false, message: 'Missing required fields (Full Name, Email, Password).' });
    }

    if (password.length < 6) {
        return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long.' });
    }

    try {
        // HASH the password before saving
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
        
        const newAdmin = new Admin({
            fullName,
            email,
            passwordHash,
        });

        const savedAdmin = await newAdmin.save();

        console.log('\n✅ Admin Account Successfully Created & Stored (MongoDB Save)');
        console.log('New Admin ID:', savedAdmin._id);
        console.log('------------------------------------------------------------');

        // Send Success Response
        res.status(201).json({ 
            success: true, 
            message: 'Admin account created successfully. Please log in.',
            adminId: savedAdmin._id
        });

    } catch (dbError) {
        console.error('MongoDB Save Error (Admin Registration):', dbError);
        // Catch unique email violation (error code 11000)
        if (dbError.code === 11000) {
            return res.status(409).json({ 
                success: false, 
                message: 'This email is already registered as an Admin.' 
            });
        }
        return res.status(500).json({ 
            success: false, 
            message: 'A server error occurred during admin registration.' 
        });
    }
});

// POST endpoint for Admin Login (Does NOT require token, generates one)
app.post('/api/admins/login', async (req, res) => {
    const { adminId, password } = req.body; // adminId is the email
    
    console.log(`\n--- Attempting Login for Admin: ${adminId} ---`);

    // --- SERVER-SIDE VALIDATION ---
    if (!adminId || !password) {
        return res.status(400).json({ success: false, message: 'Missing Admin ID or Password.' });
    }

    try {
        // 1. Find the admin by email
        const admin = await Admin.findOne({ email: adminId.toLowerCase() });

        if (!admin) {
            console.log('❌ Login Failed: Admin not found.');
            return res.status(401).json({ success: false, message: 'Invalid Admin ID or Password.' });
        }

        // 2. Check the password using bcrypt.compare()
        const isMatch = await bcrypt.compare(password, admin.passwordHash);

        if (isMatch) {
            // 🚨 Generate a REAL JWT token
            const token = jwt.sign(
                { 
                    id: admin._id, 
                    email: admin.email,
                    role: admin.role
                }, 
                JWT_SECRET, 
                { expiresIn: '24h' } // Token expires in 24 hour
            );
        
            // 3. Successful Login: Send the real token
            console.log(`✅ Admin Login Successful for ${admin.fullName}. JWT generated.`);
            res.status(200).json({ 
                success: true, 
                message: 'Login successful. Proceed to dashboard.',
                token: token, // Real JWT 
                adminName: admin.fullName
            });
        } else {
            console.log('❌ Login Failed: Incorrect password.');
            res.status(401).json({ success: false, message: 'Invalid Admin ID or Password.' });
        }

    } catch (error) {
        console.error('Error during Admin Login/Password Compare:', error);
        res.status(500).json({ success: false, message: 'A server error occurred during login.' });
    }
});
// Add this block near your other API routes in server.js
// ----------------------------------------------------
// --- API for ACCOUNT STATUS UPDATE (PROTECTED) ---
// ----------------------------------------------------
// 🚨 NEW PROTECTED ROUTE for manage-user-status.html
app.post('/api/accounts/status', verifyAdminToken, async (req, res) => {
    // Expected body: { userId, newStatus, adminName, reason }
    const { userId, newStatus, adminName, reason } = req.body;

    console.log(`\n--- Received Status Update Request from Admin ${adminName} ---`);
    console.log(`Details: User ${userId}, New Status: ${newStatus}, Reason: ${reason}`);

    // --- 1. Basic Validation ---
    if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ success: false, message: 'Invalid user ID format.' });
    }
    if (!newStatus || !reason || !adminName) {
        return res.status(400).json({ success: false, message: 'Missing required fields: newStatus, adminName, or reason.' });
    }
    if (reason.length < 10) {
        return res.status(400).json({ success: false, message: 'Justification reason must be at least 10 characters long.' });
    }

    // Normalize incoming status (e.g., 'active' -> 'Active') for consistent database storage
    const normalizedStatus = newStatus.charAt(0).toUpperCase() + newStatus.slice(1).toLowerCase();

    // The status values match the enum in the User Schema.
    // NOTE: 'Reactivate' sends 'active', so 'Reactivated' is not needed here.
    const allowedStatuses = ['Active', 'Suspended', 'Restricted', 'Locked', 'Blocked', 'Closed'];

    if (!allowedStatuses.includes(normalizedStatus)) {
        // This case handles if someone tries to submit an invalid status value
        return res.status(400).json({ success: false, message: `Invalid status value: ${newStatus}.` });
    }

    try {
        // --- 2. Perform Update ---
        const updateResult = await User.findByIdAndUpdate(
            userId, 
            { $set: { status: normalizedStatus } }, 
            { new: true, runValidators: true } // 'new: true' returns the updated document
        ).select('status fullName');

        if (!updateResult) {
            console.log(`❌ Status Update Failed: User ID ${userId} not found.`);
            return res.status(404).json({ success: false, message: 'User not found for status update.' });
        }
        
        console.log(`✅ Status Update Success! User ${updateResult.fullName} is now ${updateResult.status}.`);

        // --- 3. Success Response ---
        res.status(200).json({
            success: true,
            message: `User status successfully changed to ${updateResult.status}.`,
            newStatus: updateResult.status 
        });

    } catch (error) {
        console.error('Database/Update Error (Status Change):', error);
        // Specifically check for validation errors from the User schema
        if (error.name === 'ValidationError') {
            return res.status(400).json({ success: false, message: error.message });
        }
        res.status(500).json({ success: false, message: 'Server error during account status update.' });
    }
});

// ----------------------------------------------------------------
// --- API for ADMIN VIEW SINGLE DEPOSIT (admin-check-deposit) ---
// ----------------------------------------------------------------
// 🚨 PROTECTED ROUTE (Requires admin JWT token)
app.get('/api/check-deposits/:depositId', verifyAdminToken, async (req, res) => {
    const { depositId } = req.params;
    console.log(`\n--- Received GET Request for Deposit ID: ${depositId} ---`);

    try {
        // Find by the human-readable depositId and exclude internal fields
        const deposit = await CheckDeposit.findOne({ depositId }).select('-__v');

        if (!deposit) {
            console.log(`❌ Deposit ID ${depositId} not found.`);
            return res.status(404).json({ success: false, message: 'Check Deposit not found.' });
        }
        
        console.log(`✅ Deposit details fetched for ${depositId}.`);
        res.status(200).json(deposit);

    } catch (error) {
        console.error(`Error fetching deposit ${depositId}:`, error);
        res.status(500).json({ success: false, message: 'Server error while retrieving deposit data.' });
    }
});

// ----------------------------------------------------------------
// --- API for ADMIN STATUS UPDATE (admin-check-deposit submission) ---
// ----------------------------------------------------------------
// 🚨 PROTECTED ROUTE (Requires admin JWT token)
app.put('/api/check-deposits/:depositId', verifyAdminToken, async (req, res) => {
    const { depositId } = req.params;
    const { status, adminNotes } = req.body;
    console.log(`\n--- Received PUT Request to update Deposit ID: ${depositId} to ${status} ---`);

    // 1. Input Validation
    if (!status) {
        return res.status(400).json({ success: false, message: 'New status is required.' });
    }

    const newStatus = status.toLowerCase();
    const isRejectedOrFailed = ['failed', 'declined'].includes(newStatus);
    const trimmedNotes = (adminNotes || '').trim();

    // Enforce Admin Notes for rejection/failure (Frontend validation mirror)
    if (isRejectedOrFailed && trimmedNotes.length < 5) {
        return res.status(400).json({ success: false, message: `Admin notes (min 5 characters) are mandatory for status: ${status}.` });
    }
    
    // 2. Prepare Update Payload
    let changes = { 
        status: newStatus, 
        adminNotes: trimmedNotes,
        updatedAt: new Date()
    };
    
    try {
        // Find the original deposit document
        const deposit = await CheckDeposit.findOne({ depositId });
        if (!deposit) {
            return res.status(404).json({ success: false, message: 'Deposit not found for update.' });
        }
        
        // 3. CRITICAL: Handle the financial transaction for 'completed' (Approved) status
        if (deposit.status !== 'completed' && newStatus === 'completed') {
            console.log(`💰 Processing credit for Deposit ${depositId}.`);
            
            // Find the user's account matching the deposit currency
            const user = await User.findById(deposit.userId);
            if (!user) throw new Error('User account not found.');

            const targetAccount = user.accounts.find(a => a.currencyCode === deposit.currencyCode);
            if (!targetAccount) throw new Error(`User does not have an account in currency ${deposit.currencyCode}.`);
            
            // Update the user's account balance within a transaction (recommended)
            // For simplicity here, we'll just update:
            targetAccount.balance += deposit.amount;

            // Save both deposit status and user balance in one go
            await user.save(); 
            // The status update will happen in the findByIdAndUpdate call below.

            console.log(`✅ User ${user.fullName}'s account updated. New balance: ${targetAccount.balance.toFixed(2)} ${deposit.currencyCode}.`);
        }

        // 4. Perform the MongoDB update (using findOneAndUpdate for atomic status change)
        const updatedDeposit = await CheckDeposit.findOneAndUpdate(
            { depositId: depositId }, 
            { $set: changes }, 
            { new: true, runValidators: true }
        ).select('-__v');

        if (!updatedDeposit) {
            return res.status(500).json({ success: false, message: 'Update failed, deposit not found after initial check.' });
        }

        console.log(`✅ Deposit ${depositId} status updated to ${newStatus}.`);
        res.status(200).json({ 
            success: true, 
            message: `Deposit ${depositId} status updated to ${newStatus.toUpperCase()}.`,
            deposit: updatedDeposit
        });

    } catch (dbError) {
        console.error('MongoDB Update Error (Check Deposit):', dbError);
        res.status(500).json({ success: false, message: `Server error during deposit status update: ${dbError.message}` });
    }
});

/**
 * POST /api/cards/generate
 * Finalizes and saves the new bank card details to the MongoDB Card collection.
 * Requires admin authorization.
 * 🚨 FIX: Replaced 'adminAuthMiddleware' with the correct function name 'verifyAdminToken'
 */
app.post('/api/cards/generate', verifyAdminToken, async (req, res) => {
    const cardData = req.body;
    console.log('Received card generation request. Data:', cardData);

    const { userId, cardHolderName, cardNumber, expiryDate, cvv } = cardData;

    // 1. Basic Validation
    if (!userId || !cardHolderName || !cardNumber || !expiryDate || !cvv) {
        return res.status(400).json({ message: 'Missing required card data (userId, cardHolderName, cardNumber, expiryDate, or cvv).' });
    }

    try {
        // 2. Validate User Existence (ensure the card is linked to a real user)
        if (!mongoose.Types.ObjectId.isValid(userId)) {
             return res.status(400).json({ message: 'Invalid User ID format in payload.' });
        }
        const userExists = await User.exists({ _id: userId });
        if (!userExists) {
            return res.status(404).json({ message: `User ID ${userId} does not exist.` });
        }
        
        // 3. Create the Card Document using the Mongoose Model
        const newCard = new Card({
            userId: userId,
            cardHolderName: cardHolderName,
            cardNumber: cardNumber, // Stored without spaces (frontend removes them)
            expiryDate: expiryDate,
            cvv: cvv,
            generatedByAdmin: req.admin.id, // Get admin ID from JWT payload (now using req.admin.id from verifyAdminToken)
            status: 'Active'
        });

        // 4. Save to MongoDB
        await newCard.save();
        
        console.log(`Card successfully saved to MongoDB. ID: ${newCard._id}`);
        
        // 5. Success Response
        res.status(201).json({ 
            message: 'Card finalized and saved successfully.',
            cardDetails: { id: newCard._id, userId: newCard.userId, cardNumber: newCard.cardNumber }
        });

    } catch (error) {
        console.error('Error finalizing card:', error);
        
        // Handle unique constraint error (e.g., if card number already exists)
        if (error.code === 11000) {
            return res.status(409).json({ message: 'Card number already exists in the database. Please generate a new one.' });
        }
        // Handle validation errors (e.g., if data types are wrong)
        if (error.name === 'ValidationError') {
            return res.status(400).json({ message: `Validation Error: ${error.message}` });
        }
        
        res.status(500).json({ message: 'Internal Server Error while saving the card.' });
    }
});

/**
 * PUT /api/cards/:userId/status
 * Finds the card associated with the :userId and updates its 'status'.
 * Requires admin authorization.
 */
app.put('/api/cards/:userId/status', verifyAdminToken, async (req, res) => {
    const { userId } = req.params; 
    const { isFrozen } = req.body; 
    
    // 🛑 FIX IS HERE: Use uppercase strings defined in the Mongoose enum
    const newStatus = isFrozen ? 'FROZEN' : 'ACTIVE'; 

    if (typeof isFrozen !== 'boolean') {
        return res.status(400).json({ message: 'Invalid or missing status payload: { isFrozen: boolean } is required.' });
    }

    try {
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ message: 'Invalid User ID format in URL path.' });
        }

        const updatedCard = await Card.findOneAndUpdate(
            { userId: userId }, 
            { status: newStatus }, // Now correctly sets 'FROZEN' or 'ACTIVE'
            { new: true, runValidators: true } 
        );

        if (!updatedCard) {
            return res.status(404).json({ message: `Card not found for User ID ${userId}.` });
        }

        // Success Response
        res.status(200).json({
            message: `Card status updated to ${updatedCard.status}.`,
            newStatus: updatedCard.status,
            cardId: updatedCard._id
        });

    } catch (error) {
        // ... (error handling remains the same) ...
        if (error.name === 'ValidationError') {
            console.error('Mongoose Validation Error updating card status:', error.message);
            return res.status(400).json({ 
                message: `Validation Error: Could not set status to '${newStatus}'. Details: ${error.message}` 
            });
        }
        
        console.error('Unhandled Server Error updating card status:', error);
        res.status(500).json({ message: 'Internal Server Error while changing card status.' });
    }
});
/**
 * POST /api/users/:id/transactions/generate
 * Generates a specified number of mock transactions for a user, ensuring
 * that the transaction insertion and the user balance update are atomic
 * using a Mongoose Session (ACID principles).
 * Requires admin authorization.
 */
app.post('/api/users/:id/transactions/generate', verifyAdminToken, async (req, res) => {
    
    const targetUserId = req.params.id;
    const session = await mongoose.startSession(); // Start the Mongoose session
    session.startTransaction(); // Begin the transaction
    
    try {
        // PULLING parameters from the request body
        const { 
            numTransactions = 10, 
            minAmount = 5.00, 
            maxAmount = 500.00, 
            startDaysAgo = 90, 
            endDaysAgo = 0,
            descriptionPattern = "Mock Transaction at Merchant X",
            transactionType = "MIXED"
        } = req.body;

        // --- 1. Validation and Setup ---
        if (numTransactions < 1 || numTransactions > 500) {
            await session.abortTransaction();
            return res.status(400).json({ message: 'Invalid number of transactions (must be between 1 and 500).' });
        }
        
        // Define date range
        const now = new Date();
        const startDate = new Date(now.getTime() - startDaysAgo * 24 * 60 * 60 * 1000);
        const endDate = new Date(now.getTime() - endDaysAgo * 24 * 60 * 60 * 1000);

        // --- 2. Database Check: Find User and Accounts (Using Nested Schema) ---
        // CRITICAL: Use { session } in findById to lock the document for this transaction
        let user = await User.findById(targetUserId).session(session); 
        let targetAccount;

        if (!mongoose.Types.ObjectId.isValid(targetUserId)) {
            await session.abortTransaction();
            return res.status(400).json({ message: 'Invalid user ID format.' });
        }
        
        if (!user) {
            await session.abortTransaction();
            return res.status(404).json({ message: `User with ID ${targetUserId} not found.` });
        }

        // Find the user's primary account or create one if necessary
        if (user.accounts.length === 0) {
            const newAccount = {
                currencyCode: user.currency || 'USD',
                accountNumber: `MOCK-${Math.floor(Math.random() * 10000000000)}`,
                domesticRouting: '000000000',
                balance: 1000.00,
                accountType: 'Checking'
            };
            user.accounts.push(newAccount);
            // We save the user later in the transaction, but we set the target account now
            targetAccount = user.accounts[0];
        } else {
             targetAccount = user.accounts.find(acc => acc.accountType === 'Checking') || user.accounts[0];
        }
        
        if (!targetAccount) {
            await session.abortTransaction();
            return res.status(404).json({ message: `User has no valid accounts to attach transactions to.` });
        }
        
        // --- 3. Generate Transactions ---
        const transactionsToSave = [];

        for (let i = 0; i < numTransactions; i++) {
            const rawAmount = parseFloat(getRandomAmount(minAmount, maxAmount));
            const isCredit = Math.random() < 0.5;
            const finalAmount = isCredit ? rawAmount : -rawAmount; 
            
            const newTransaction = {
                userId: targetUserId,
                accountNumber: targetAccount.accountNumber,
                accountType: targetAccount.accountType,
                referenceId: `${targetUserId.substring(0, 8)}-${Date.now()}-${i}-${Math.random().toString(36).substring(2, 6)}`, 
                amount: finalAmount, 
                description: getRandomDescription(isCredit, descriptionPattern), 
                date: getRandomDate(startDate, endDate) 
            };
            
            transactionsToSave.push(newTransaction);
        }

        // --- 4. Atomic Database Operation (Transaction and Balance Update) ---

        // 1. Save the new transactions, passing the session object
        const insertedTransactions = await Transaction.insertMany(transactionsToSave, { session });
        
        // 2. Calculate the net change
        const netChange = insertedTransactions.reduce((sum, t) => sum + t.amount, 0);
        
        // 3. Find the index of the modified account
        const accountIndex = user.accounts.findIndex(acc => acc.accountNumber === targetAccount.accountNumber);

        if (accountIndex !== -1) {
            // 4. Update the balance
            user.accounts[accountIndex].balance += netChange;
            
            // 5. Tell Mongoose the nested array element has been modified
            user.markModified('accounts');
            
            // 6. Save the user document (in the session)
            await user.save({ session });
            
            // Update the local targetAccount for the response
            targetAccount = user.accounts[accountIndex];
        } else {
            // If the account somehow disappeared, roll back everything
            console.error("CRITICAL ERROR: Account not found in user's array for balance update. Rolling back.");
            await session.abortTransaction();
            return res.status(500).json({ message: 'Internal error: Account mismatch during balance update.' });
        }
        
        // 7. COMMIT: If we reached this point, all changes are correct.
        await session.commitTransaction();
        
        console.log(`✅ Successfully generated and inserted ${insertedTransactions.length} transactions for user ${targetUserId}. Net change: ${netChange.toFixed(2)}`);

        res.status(201).json({ 
            message: `Successfully generated ${insertedTransactions.length} transactions.`, 
            userId: targetUserId,
            count: insertedTransactions.length,
            newBalance: targetAccount.balance.toFixed(2) // Return the new balance
        });
        
    } catch (e) {
        // --- Error Handling and Rollback ---
        console.error("❌ Error during atomic transaction (Rolling back):", e);
        await session.abortTransaction(); // Ensure rollback on ANY failure
        
        // Simplified error response logic (kept mostly from your original)
        if (e.name === 'ValidationError') {
            return res.status(400).json({ message: 'Transaction failed Mongoose validation.', error: e.message });
        }
        
        if (e.code === 11000) {
            return res.status(500).json({ message: 'Failed to save transactions due to a duplicate reference ID. Try again.', error: e.message });
        }
        
        res.status(500).json({ 
            message: 'An unexpected server error occurred.',
            error: e.message 
        });
        
    } finally {
        session.endSession(); // Always close the session
    }
});

/**
 * PUT /api/admin/transactions/:id/complete
 * Admin action to approve and complete a 'Processing' transfer.
 * 1. Checks if the transfer is internal/external.
 * 2. If INTERNAL, credits the destination account and creates the credit transaction record.
 * 3. Updates the original (debit) transaction status to 'Successful'.
 * 4. Notifies the user.
 */
app.put('/api/transactions/:id/complete', verifyAdminToken, async (req, res) => {
    
    const transactionId = req.params.id;
    let session;

    console.log(`\n--- Received Admin Completion Request for TX ID: ${transactionId} ---`);
    
    try {
        session = await mongoose.startSession();
        session.startTransaction();

        // 1. Find the Debit Transaction and Lock it
        const debitTx = await Transaction.findById(transactionId).session(session);

        if (!debitTx) {
            await session.abortTransaction();
            return res.status(404).json({ success: false, message: 'Transaction record not found.' });
        }

        if (debitTx.status === 'Successful' || debitTx.status === 'Failed') {
            await session.abortTransaction();
            return res.status(409).json({ success: false, message: `Transaction already finalized with status: ${debitTx.status}.` });
        }

        if (debitTx.status !== 'Processing' || !debitTx.details) {
            await session.abortTransaction();
            return res.status(409).json({ success: false, message: 'Transaction status is not "Processing" or missing necessary details for completion.' });
        }

        const { destinationAccountNumber, destinationName, transferType, transactionClass } = debitTx.details;
        const transferAmount = Math.abs(debitTx.amount); // Debit amount is stored as negative
        
        let userToNotify = null; // Will store the user document
        
        // 2. Handle Internal Transfer (Credit Leg)
        if (transactionClass === 'INTERNAL_DEBIT') {
            
            // Find the User and Lock the document
            userToNotify = await User.findById(debitTx.userId).session(session).select('accounts email currency').lean();
            if (!userToNotify) { await session.abortTransaction(); return res.status(404).json({ success: false, message: 'Source user not found for crediting.' }); }

            const destinationAccount = userToNotify.accounts.find(a => a.accountNumber === destinationAccountNumber);
            
            if (!destinationAccount) {
                await session.abortTransaction();
                // Admin must manually fix this, or the transfer fails
                return res.status(404).json({ success: false, message: 'Internal destination account not found on user profile. Transfer aborted.' });
            }

            const newDestinationBalance = destinationAccount.balance + transferAmount;

            // 2A. Credit the Destination Account Balance
            await User.updateOne(
                { _id: debitTx.userId, 'accounts.accountNumber': destinationAccountNumber },
                { $set: { 'accounts.$.balance': newDestinationBalance } },
                { session: session, runValidators: true }
            );

            // 2B. Create the Credit Transaction History Record
            const creditReferenceId = `${debitTx.referenceId}-CR`; 

            await Transaction.create([{ 
                userId: debitTx.userId, 
                date: new Date(), 
                amount: transferAmount, // POSITIVE amount (Credit)
                description: `Internal Credit from ${debitTx.accountNumber.slice(-4)} (Ref: ${debitTx.referenceId.slice(-6)})`, 
                accountNumber: destinationAccount.accountNumber, 
                accountType: destinationAccount.accountType, 
                referenceId: creditReferenceId, 
                status: 'Successful', // <-- FINAL STATUS
                details: {
                    sourceReferenceId: debitTx.referenceId // Link back to the original debit
                }
            }], { session: session });
        }

        // 3. Update the Original Debit Transaction Status
        await Transaction.updateOne(
            { _id: transactionId },
            { $set: { status: 'Successful' } }, // <-- FINAL STATUS for Debit
            { session: session }
        );

        // 4. Commit Transaction
        await session.commitTransaction();
        
        // 5. Notify the User (after commit)
        if (!userToNotify) {
            // Fetch user info just for the email notification if it wasn't an internal transfer
            userToNotify = await User.findById(debitTx.userId).select('email').lean();
        }
        
        if (userToNotify) {
            const emailDetails = {
                userName: userToNotify.email, // Or actual name if available
                transactionId: debitTx.referenceId,
                newStatus: 'Successful',
            };
            // This is the function we defined earlier that sends a nicely formatted email
            sendStatusUpdateEmail(userToNotify.email, emailDetails.userName, emailDetails.transactionId, emailDetails.newStatus); 
        }

        console.log(`✅ Admin Transfer Completion Success! TX ID: ${transactionId} is now Successful.`);
        
        res.status(200).json({
            success: true,
            message: `Transaction ${transactionId} successfully completed. Recipient credited.`,
            newStatus: 'Successful'
        });

    } catch (error) {
        if (session) { await session.abortTransaction().catch(() => {}); }
        console.error('Database/Admin Completion Error:', error);
        res.status(500).json({ success: false, message: error.message || 'Server error during transaction completion.' });
    } finally {
        if (session) { session.endSession(); }
    }
});



// POST endpoint for User/Client Login (MODIFIED FOR EMAIL LOGIN AND 2FA INITIATION)
app.post('/api/users/login', async (req, res) => {
    // We now accept an identifier that can be either userIdName or the user's email
    const { loginIdentifier, userPassword } = req.body; 
    
    console.log(`\n--- Attempting Login for Identifier: ${loginIdentifier} (2FA Initiation) ---`);

    // --- SERVER-SIDE VALIDATION ---
    if (!loginIdentifier || !userPassword) {
        return res.status(400).json({ success: false, message: 'Missing Identifier or Password.' });
    }

    try {
        // 1. Find the user by userIdName OR email (case-insensitive search for both)
        const user = await User.findOne({ 
            $or: [
                { userIdName: loginIdentifier.toLowerCase() },
                { email: loginIdentifier.toLowerCase() }
            ]
        });

        if (!user) {
            console.log('❌ Login Failed: User not found or identifier invalid.');
            return res.status(401).json({ success: false, message: 'Invalid User ID/Email or Password.' });
        }
        
        // Check account status
        if (user.status !== 'Active') {
            console.log(`❌ Login Failed: User account status is ${user.status}.`);
            return res.status(403).json({ success: false, message: `Account is ${user.status}. Please contact support.` });
        }

        // 2. Check the password using bcrypt.compare()
        const isMatch = await bcrypt.compare(userPassword, user.passwordHash);

        if (isMatch) {
            // 🚨 2FA LOGIC: Password is correct. Trigger REAL OTP workflow.
            
            if (!user.email) {
                console.log(`❌ OTP Failed: User ${user.userIdName} has no registered email for 2FA.`);
                return res.status(500).json({ success: false, message: '2FA setup incomplete. Please contact support.' });
            }
            
            // --- REAL OTP GENERATION AND EMAIL SENDING ---
            await generateAndSendOtp(user); // Now uses the new, correctly defined helper
            // ---------------------------------------------
            
            const maskedAddress = maskEmail(user.email);
            console.log(`✅ User Password Match for ${user.fullName}. OTP SENT to ${maskedAddress}. Proceeding to OTP verification step.`);
            
            // Respond with 202 (Accepted) to tell the client to proceed to the verification form.
            return res.status(202).json({ 
                success: true, 
                message: 'Password verified. Proceeding to security check.',
                nextStep: 'VERIFY_OTP', 
                // Send back the identifier used for the first step to be used in the second step
                loginIdentifier: loginIdentifier,
                maskedEmail: maskedAddress 
            });
            
        } else {
            console.log('❌ Login Failed: Incorrect password.');
            res.status(401).json({ success: false, message: 'Invalid User ID/Email or Password.' });
        }

    } catch (error) {
        // This catch handles DB lookups, bcrypt errors, AND errors thrown by generateAndSendOtp (e.g., email failure)
        console.error('Error during User Login/2FA Initiation:', error);
        // The error message from the email function is propagated here
        const errorMessage = error.message.includes('verification code') ? error.message : 'A server error occurred during login.';
        res.status(500).json({ success: false, message: errorMessage });
    }
});

// ------------------------------------------------------------------------------------------------
// --- NEW POST endpoint for OTP Verification (2FA completion) ---
// ------------------------------------------------------------------------------------------------
app.post('/api/users/verify-otp', async (req, res) => {
    // Requires the identifier (userIdName/email) and the OTP code entered by the user
    const { loginIdentifier, otpCode } = req.body; 

    console.log(`\n--- Received OTP Verification Request for Identifier: ${loginIdentifier} ---`);

    if (!loginIdentifier || !otpCode) {
        return res.status(400).json({ success: false, message: 'Missing identifier or OTP code.' });
    }

    try {
        // 1. Find the user using the identifier provided during the login process
        const user = await User.findOne({ 
            $or: [
                { userIdName: loginIdentifier.toLowerCase() },
                { email: loginIdentifier.toLowerCase() }
            ]
        });

        if (!user) {
            console.log('❌ Verification Failed: User not found for identifier.');
            return res.status(401).json({ success: false, message: 'Unauthorized access attempt.' });
        }
        
        // 2. Check if an OTP is currently set for this user (CORRECTED FIELD NAMES)
        if (!user.otpHash || !user.otpExpiration) {
            console.log(`❌ Verification Failed: No pending OTP for user ${user.userIdName}.`);
            // Avoid leaking information about whether an OTP was requested
            return res.status(401).json({ success: false, message: 'Invalid OTP or session expired.' }); 
        }

        // 3. Check if the OTP has expired (CORRECTED FIELD NAMES)
        if (new Date() > user.otpExpiration) {
            // Clear the expired OTP data to prevent reuse (CORRECTED FIELD NAMES)
            user.otpHash = null;
            user.otpExpiration = null;
            await user.save();
            
            console.log(`❌ Verification Failed: OTP expired for user ${user.userIdName}.`);
            return res.status(401).json({ success: false, message: 'OTP expired. Please try logging in again.' });
        }

        // 4. Compare the user's plain text OTP against the HASHED secret (CORRECTED FIELD NAME)
        const otpMatch = await bcrypt.compare(otpCode, user.otpHash);

        if (otpMatch) {
            // ✅ SUCCESS: OTP MATCHED
            console.log(`✅ Verification Success for user ${user.userIdName}. Generating token.`);

            // a. Clear the OTP details immediately (important security step) (CORRECTED FIELD NAMES)
            user.otpHash = null;
            user.otpExpiration = null;

            // b. Generate a JWT token for the session
            const token = generateClientToken(user);

            // c. Save the cleared OTP state
            await user.save(); 

            // d. Respond with the success token and necessary client data
            return res.status(200).json({ 
                success: true, 
                message: 'Login successful. OTP verified.',
                token: token, 
                userIdName: user.userIdName,
                fullName: user.fullName
            });

        } else {
            // ❌ FAILURE: OTP DID NOT MATCH
            console.log(`❌ Verification Failed: Invalid OTP for user ${user.userIdName}.`);
            // We do NOT clear the OTP here, allowing the user a few more tries until expiry.
            return res.status(401).json({ success: false, message: 'Invalid OTP. Please check the code sent to your email.' });
        }

    } catch (error) {
        console.error('Error during OTP Verification:', error);
        res.status(500).json({ success: false, message: 'A server error occurred during verification.' });
    }
});

// --- NEW POST endpoint for OTP Resend (Resends the existing code or generates a new one) ---
app.post('/api/users/resend-otp', async (req, res) => {
    const { loginIdentifier } = req.body; 

    if (!loginIdentifier) {
        return res.status(400).json({ success: false, message: 'Missing identifier.' });
    }

    try {
        const user = await User.findOne({ 
            $or: [
                { userIdName: loginIdentifier.toLowerCase() },
                { email: loginIdentifier.toLowerCase() }
            ]
        });

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        
        // Check if an OTP is already active, if so, just resend it (or regenerate/resend for security)
        // Here, we'll follow the logic of re-generating and re-sending an OTP.
        await generateAndSendOtp(user); 
        
        const maskedAddress = maskEmail(user.email);
        console.log(`✅ OTP Re-sent to ${maskedAddress}.`);
        
        return res.status(200).json({ 
            success: true, 
            message: `A new verification code has been sent to ${maskedAddress}.`
        });

    } catch (error) {
        console.error('Error during OTP Resend:', error);
        res.status(500).json({ success: false, message: 'Failed to re-send OTP.' });
    }
});

// ------------------------------------------------------------------------------------------------
// --- CLIENT DASHBOARD API (CORRECTED: REMOVED Math.abs() from Account Balance) ---
// ------------------------------------------------------------------------------------------------
app.get('/api/client/dashboard', verifyClientToken, async (req, res) => {
    
    // 1. Get the User ID (which is the username string) from the token payload.
    const username = req.user.userIdName; 

    if (!username) {
        console.error('CRITICAL ERROR: Username (userIdName) not found in token payload.');
        return res.status(401).json({ success: false, message: 'Authorization error: Missing user identifier in token.' });
    }
    
    console.log(`\n--- Received Dashboard Request for Username: ${username} ---`);

    try {
        // 2. Use User.findOne to query the specific username field.
        // We use .populate('accounts.currency') if currency is a separate model, otherwise it's fine.
        const user = await User.findOne({ userIdName: username }).select('fullName profilePicturePath accounts currency email'); 

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found in database using username.' });
        }
        
        // ❌ REMOVED FIX: No Math.abs() is needed here. The balance is returned as stored.
        // We still map the accounts to ensure they are plain objects.
        const processedAccounts = user.accounts.map(account => account.toObject());
        const recentTransactions = await Transaction.find({ userId: user._id })
            // Ensure status is Successful or Refunded to show completed events
            .where('status').in(['Successful', 'Refunded']) 
            .sort({ timestamp: -1 }) // Assuming 'timestamp' or 'date' is the correct field for sorting
            .limit(10)
            .select('description date amount accountType status'); // Added 'status' to the select
        
        console.log(`Fetched ${recentTransactions.length} recent transactions for the dashboard.`);

        // 4. Consolidate and Send Response
        const dashboardData = {
            fullName: user.fullName,
            greetingName: user.fullName.split(' ')[0],
            email: user.email,
            profilePicturePath: user.profilePicturePath,
            accounts: processedAccounts, // ⬅️ ACCOUNTS RETURNED AS-IS (NO Math.abs)
            currency: user.currency,
            transactions: recentTransactions, 
        };

        console.log(`✅ Dashboard data fetched for ${user.fullName}.`);
        res.status(200).json({ success: true, data: dashboardData });

    } catch (error) {
        // ... (error handling) ...
        console.error('CRITICAL SERVER ERROR during dashboard retrieval:', error); 
        res.status(500).json({ success: false, message: 'Server error while retrieving dashboard data.' });
    }
});
// -----------------------------------------------------------
// --- HELPER FUNCTION FOR CLIENT PROFILE RETRIEVAL (NEW) ---
// -----------------------------------------------------------

/**
 * Fetches user data from MongoDB using the ID from the token 
 * and transforms it for the client profile page response.
 * @param {string} userId - The MongoDB ObjectId of the user.
 * @returns {object | null} - Transformed profile data or null.
 */
async function fetchClientProfileFromDB(userId) {
    // Select all fields *except* sensitive hashes for client-side display
    // NOTE: 'User' must be imported/defined (e.g., from mongoose model) in the environment where this runs.
    const userDoc = await User.findById(userId).select('-passwordHash -transferPinHash -__v').lean(); 
    
    if (!userDoc) {
        return null;
    }

    // Assumes the DB 'address' field is a delimited string (Line1|Line2|City|State|Zip) and splits it for the client.
    // Ensure we handle cases where userDoc.address might be null or undefined
    const addressParts = userDoc.address ? userDoc.address.split('|') : [];
    const [addressLine1, addressLine2, city, state, zipCode] = addressParts;


    return {
        // Core Profile Information
        id: userDoc._id,
        userIdName: userDoc.userIdName,
        fullName: userDoc.fullName,
        greetingName: userDoc.fullName.split(' ')[0], // First name for greeting
        email: userDoc.email, // CORRECTED: Use the actual email from the database
        profilePicturePath: userDoc.profilePicturePath,

        // Contact/Address Information (Split from single DB field)
        addressLine1: addressLine1 || '',
        addressLine2: addressLine2 || '',
        city: city || '',
        state: state || '',
        zipCode: zipCode || '',
        occupation: userDoc.occupation,
        gender: userDoc.gender,
        dob: userDoc.dob ? userDoc.dob.toISOString().split('T')[0] : '', // Format date for client input

        // Financial/Status
        currency: userDoc.currency,
        status: userDoc.status,
        accounts: userDoc.accounts, // Send the full accounts array
    };
}


app.get('/api/client/messages', verifyClientToken, async (req, res) => {
    
    // The user's ID is retrieved from the authenticated token payload (req.user.id, which is set by verifyClientToken)
    // Note: This API endpoint is now redundant if the client uses the dashboard endpoint to fetch messages, 
    // but it serves as a dedicated, minimalist message endpoint if required.
    const userId = req.user.id; 
    console.log(`\n--- Received GET Request for Client Messages for User ID: ${userId} ---`);

    try {
        // 1. Find the user and SELECT ONLY the message field (announcementMessage)
        // 🚨 FIX: Removed 'issueMessage' from the selection
        const user = await User.findById(userId).select('announcementMessage');

        if (!user) {
            console.log(`❌ User ID ${userId} not found.`);
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        // 2. Return the clean message object
        // 🚨 FIX: Removed 'issueMessage' from the response
        const responseData = {
            success: true,
            announcementMessage: user.announcementMessage,
        };

        console.log(`✅ Client messages fetched successfully for ${userId}.`);
        res.status(200).json(responseData);

    } catch (error) {
        console.error(`Error fetching client messages for user ${userId}:`, error);
        res.status(500).json({ success: false, message: 'Server error while retrieving client messages.' });
    }
});

// -------------------------------------------------------------------------
// --- API for GET CLIENT PROFILE (Fixes the original 404 error) ---
// -------------------------------------------------------------------------
// 🚨 PROTECTED ROUTE
app.get('/api/client/profile', verifyClientToken, async (req, res) => {
    // req.user contains the decoded JWT payload (id, userIdName, role)
    const userId = req.user.id;
    console.log(`\n--- Received GET Request for Client Profile (ID: ${userId}) ---`);

    try {
        const profileData = await fetchClientProfileFromDB(userId);
        
        if (!profileData) {
            console.log(`❌ Profile for client ID ${userId} not found.`);
            return res.status(404).json({ success: false, message: 'User profile not found in database.' });
        }

        // Success Response (Status 200 OK)
        // The client expects the data nested under a 'data' key: const { data } = await response.json();
        console.log(`✅ Profile data successfully fetched for ${profileData.userIdName}.`);
        res.json({
            success: true,
            data: profileData
        });

    } catch (error) {
        console.error('Error fetching client profile:', error.message);
        res.status(500).json({ success: false, message: 'Internal Server Error during profile retrieval.' });
    }
});

// ------------------------------------------------------------------------------------------------
// --- HELPER FUNCTION (included for completeness) ---
// ------------------------------------------------------------------------------------------------
/**
 * Generates a string of random digits of a specified length.
 * @param {number} length The number of digits to generate.
 * @returns {string} The random number string.
 */
const generateRandomNumber = (length) => {
    // Note: While this function works, for true uniqueness and security, 
    // consider using a library like 'uuid' or Node's 'crypto' module for IDs.
    return Math.floor(Math.random() * Math.pow(10, length))
               .toString()
               .padStart(length, '0');
};

// ------------------------------------------------------------------------------------------------
// --- API for CLIENT FUND TRANSFER (INTERNAL/EXTERNAL) ---
// ------------------------------------------------------------------------------------------------
// 🚨 NEW PROTECTED ROUTE for client-side transfers - Transfer status is now always 'Processing' initially.
app.post('/api/client/transfer', verifyClientToken, async (req, res) => {
    // 1. Get client's ID from the token
    const userId = req.user.id; 
    
    // Expected body: { sourceAccountNumber, amount, transferType, destinationName, destinationAccountNumber, destinationBank, transferPin, bankIdentifier, recipientAddress }
    const { 
        sourceAccountNumber, 
        amount, 
        transferType, 
        destinationName, 
        destinationAccountNumber, 
        destinationBank,
        transferPin // The user's secret PIN for confirming transactions
    } = req.body;
    
    const transactionAmount = parseFloat(amount);
    
    console.log(`\n--- Received Client Transfer Request from User ID: ${userId} ---`);

    // --- 2. Basic Validation ---
    if (!sourceAccountNumber || !transactionAmount || !transferType || !transferPin) {
        return res.status(400).json({ success: false, message: 'Missing required transfer fields (Source, Amount, Type, or PIN).' });
    }
    
    if (transactionAmount <= 0 || isNaN(transactionAmount)) {
        return res.status(400).json({ success: false, message: 'Amount must be a positive number.' });
    }
    
    if (!/^\d{4}$/.test(transferPin)) {
        return res.status(400).json({ success: false, message: 'Transfer PIN must be 4 digits.' });
    }
    
    // Check if the transfer is internal (stores a flag for the Transaction record)
    const isInternalTransfer = transferType.toLowerCase().includes('internal'); 
    
    // Validate destination fields if internal (optional but good practice)
    if (isInternalTransfer && !destinationAccountNumber) {
         return res.status(400).json({ success: false, message: 'Internal transfers require a destination account number.' });
    }

    // --- Mongoose Session Setup (CRITICAL for atomicity) ---
    let session;
    let referenceId; // Declare outside try scope
    let userCurrency; // Declare outside try scope

    try {
        // Start a Mongoose session for transaction atomicity (all or nothing)
        session = await mongoose.startSession();
        session.startTransaction();

        // --- 3. Find User and Validate PIN ---
        const user = await User.findById(userId)
            .session(session)
            .select('transferPinHash accounts currency transferMessage email') 
            .lean(); 

        if (!user) {
            await session.abortTransaction();
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        
        // Validate Transfer PIN using bcrypt
        const isPinMatch = await bcrypt.compare(transferPin, user.transferPinHash);
        
        if (!isPinMatch) {
            await session.abortTransaction();
            console.log('❌ Transfer Failed: Invalid Transfer PIN.');
            return res.status(403).json({ success: false, message: 'Invalid Transfer PIN. Transaction aborted.' });
        }
        
        // --- 3.5. CHECK FOR CONDITIONAL TRANSFER MESSAGE BLOCK (POLICY) ---
        const messageConfig = user.transferMessage || {};
        if (messageConfig.isActive === true) {
            await session.abortTransaction();
            console.log(`⚠️ Transfer Blocked: Conditional message is active for user ${userId}.`);
            return res.status(409).json({ 
                success: false, 
                message: 'Transaction blocked by administrator policy.',
                conditionalMessage: messageConfig.messageContent,
                policyType: 'ADMIN_POLICY'
            });
        }

        // --- 4. Locate and Verify Source Account and Balance ---
        const sourceAccount = user.accounts.find(a => a.accountNumber === sourceAccountNumber);

        if (!sourceAccount) {
            await session.abortTransaction();
            return res.status(404).json({ success: false, message: 'Source account not found for this user.' });
        }

        // 🔑 DEBUG LOG: Check the balance the server sees
        console.log(`[SERVER CHECK] Account: ${sourceAccountNumber.slice(-4)}, Balance: ${sourceAccount.balance.toFixed(2)} ${user.currency}. Transfer Amount: ${transactionAmount.toFixed(2)}`);
        
        // --- 4.1. Calculate Potential New Balance and Enforce Zero Floor ---
        const newBalance = sourceAccount.balance - transactionAmount;
        userCurrency = user.currency; 

        // 🔑 STRICT ZERO BALANCE CHECK: If the new balance is negative, block the transfer.
        if (newBalance < 0) {
            await session.abortTransaction();
            console.log('❌ Transfer Failed: Insufficient Funds (Strict Zero Balance Policy).');
            
            const currentBalanceMessage = `Your available balance of ${sourceAccount.balance.toFixed(2)} ${userCurrency} is insufficient for this transfer of ${transactionAmount.toFixed(2)} ${userCurrency}. Overdrafts are not permitted.`;

            return res.status(409).json({ 
                success: false, 
                message: 'Transaction aborted due to insufficient funds (Zero Balance Policy).',
                conditionalMessage: currentBalanceMessage,
                policyType: 'ZERO_BALANCE_BREACH'
            });
        }

        // --- 5. Perform the Debit Operation (Update Balance) ---
        const updateResult = await User.updateOne(
            { _id: userId, 'accounts.accountNumber': sourceAccountNumber },
            { $set: { 'accounts.$.balance': newBalance } }, 
            { session: session, runValidators: true }
        );
        
        if (updateResult.modifiedCount === 0) {
            await session.abortTransaction();
            throw new Error('Failed to update source account balance. Check account number and user ID.');
        }

        // --- 6. Create Transaction History Record (Debit) ---
        const destinationAccountInfo = isInternalTransfer 
            ? `Internal Account (${destinationAccountNumber.slice(-4)})` 
            : `${destinationName || 'External Account'} (${destinationAccountNumber ? destinationAccountNumber.slice(-4) : 'N/A'})`;
            
        const transactionDescription = `Transfer: ${transferType} to ${destinationAccountInfo}`;
        
        // 🔑 Generate the base reference ID only once for the whole transfer operation
        referenceId = `TXN-${Date.now()}-${generateRandomNumber(10)}`; 

        await Transaction.create([{ 
            userId: user._id, 
            date: new Date(), 
            amount: -transactionAmount, // NEGATIVE amount (Debit)
            description: transactionDescription, 
            accountNumber: sourceAccount.accountNumber, 
            accountType: sourceAccount.accountType, 
            referenceId: referenceId, // Base ID for Debit
            // 🛑 MODIFICATION: Status is now MANDATORILY 'Processing'
            status: 'Processing',
            // 🔑 NEW FIELDS for Admin API to process the credit/completion later
            isInternal: isInternalTransfer,
            destinationAccountNumber: destinationAccountNumber,
            destinationName: destinationName || 'N/A',
            destinationBank: destinationBank || 'N/A',
        }], { session: session });

        // ------------------------------------------------------------------
        // --- 6.5. CRITICAL MODIFICATION: INTERNAL CREDIT LOGIC REMOVED ---
        // The credit of the destination account is now handled by the Admin API 
        // when the transaction status is updated from 'Processing' to 'Successful'.
        // ------------------------------------------------------------------
        
        // --- 7. Commit Transaction (CRITICAL) ---
        await session.commitTransaction();
        session.endSession();
        
        const transactionDetails = {
            formattedAmount: formatCurrency(transactionAmount, userCurrency), 
            sourceAccountNumber: sourceAccount.accountNumber,
            destinationName: destinationName || (isInternalTransfer ? 'Internal Account Transfer' : 'External Account Transfer'),
            destinationAccountNumber: destinationAccountNumber || 'N/A',
            transferType: transferType,
            referenceId: referenceId,
            newBalance: formatCurrency(newBalance, userCurrency), 
            currency: userCurrency,
            // 🛑 MODIFICATION: Status is now strictly 'Processing'
            status: 'Processing',
        };
        
        // 🔑 ACTION: Call the email function to notify of debit/pending status!
        sendTransferNotification(user.email, transactionDetails); 
        
        console.log(`✅ Client Transfer Accepted for Processing! Source Account Debited. Reference ID: ${referenceId}`);

        // --- 9. Success Response ---
        res.status(202).json({ // Use 202 Accepted for processing tasks
            success: true,
            // 🛑 MODIFICATION: Update message to reflect pending status
            message: `Transfer of ${userCurrency} ${transactionAmount.toFixed(2)} submitted for review and processing. Reference ID: ${referenceId}`,
            newBalance: newBalance,
            currency: userCurrency,
            status: 'Processing' // Explicitly state the status
        });

    } catch (error) {
        if (session) {
            await session.abortTransaction().catch(() => {}); 
            session.endSession();
        }
        console.error('Database/Client Transfer Error:', error);
        res.status(500).json({ success: false, message: error.message || 'Server error during client fund transfer.' });
    }
});

// --- 2. CLIENT CARD MANAGEMENT API (FETCH CARD DATA) ---
// 🚨 MODIFIED: CARD NUMBER MASKED AND CVV REMOVED FOR SECURITY.
app.get('/api/client/card', verifyClientToken, async (req, res) => {
    const userId = req.user.id;
    console.log(`\n--- Received Card Data Request for Client ID: ${userId} ---`);

    try {
        // Fetch User Data (For fullName)
        const user = await User.findById(userId).select('fullName');
        
        // Find the user's primary card. 
        // Ensure cardNumber and status are selected from the database
        const card = await Card.findOne({ userId: userId }).select('cardHolderName cardNumber expiryDate status');

        if (!user) {
             console.error('Failure: User not found.');
             return res.status(404).json({ success: false, message: 'User not found.' });
        }
        
        if (!card) {
             // If no card is found, return an empty set with a status.
             return res.status(200).json({ 
                 success: true, 
                 message: 'No card generated for this user.',
                 data: { hasCard: false, fullName: user.fullName }
             });
        }

        // 2. Prepare Data for Client
        // 🛡️ SECURITY FIX: Masking card number and removing CVV from client response.
        const fullCardNumber = card.cardNumber || '';
        const maskedCardNumber = fullCardNumber.length > 4 
            ? '**** **** **** ' + fullCardNumber.slice(-4) 
            : fullCardNumber;

        // ✅ FIX: The client receives the current, live card status from the database.
        // We check if the status is 'FROZEN' (case-insensitive check is safer)
        const isCardFrozen = card.status ? card.status.toUpperCase() === 'FROZEN' : false;

        const cardData = {
            hasCard: true,
            fullName: user.fullName,
            cardHolderName: card.cardHolderName,
            
            // CARD NUMBER MASKED
            displayCardNumber: maskedCardNumber, 
            
            // CVV REMOVED - NEVER SEND TO CLIENT
            cvv: null, 

            // Sending the actual boolean state derived from the database status
            isFrozen: isCardFrozen, 
            
            // Expiry Date
            expiryDate: card.expiryDate, 
        };

        console.log(`✅ Card data fetched for ${card.cardHolderName}. Status: ${card.status}. Details masked for security.`);
        res.status(200).json({ success: true, data: cardData });

    } catch (error) {
        console.error('Error fetching client card data:', error);
        if (error.name === 'CastError') {
             return res.status(400).json({ success: false, message: 'Invalid User ID format.' });
        }
        res.status(500).json({ success: false, message: 'Server error while retrieving card data.' });
    }
});

// --- NEW SECURE ENDPOINT: FETCH SENSITIVE CARD DETAILS ---
app.get('/api/client/card/sensitive', verifyClientToken, async (req, res) => {
    const userId = req.user.id;
    console.log(`\n--- Received Sensitive Card Data Request for Client ID: ${userId} ---`);

    try {
        // Fetch the Card, explicitly selecting the sensitive fields.
        const card = await Card.findOne({ userId: userId }).select('cardNumber cvv');

        if (!card) {
            console.error('Failure: Card not found for user.');
            // Use 404 if card doesn't exist, 403 or 401 if unauthorized access
            return res.status(404).json({ success: false, message: 'Card not found or not generated.' });
        }

        // Return the full card number (as a raw string) and CVV
        const sensitiveData = {
            fullCardNumber: card.cardNumber, 
            cvv: card.cvv 
        };

        console.log(`✅ Sensitive card details successfully retrieved for Client ID: ${userId}.`);
        res.status(200).json({ success: true, data: sensitiveData });

    } catch (error) {
        console.error('Error fetching sensitive card data:', error);
        res.status(500).json({ success: false, message: 'Server error while retrieving sensitive card data.' });
    }
});

// --- CLIENT CARD MANAGEMENT API (TOGGLE FREEZE STATUS) ---
// 🚨 PROTECTED ROUTE
app.post('/api/client/card/freeze', verifyClientToken, async (req, res) => {
    const userId = req.user.id;
    const { shouldFreeze } = req.body; // boolean: true to Suspend, false to Activate
    console.log(`\n--- Received Freeze Toggle Request for Client ID: ${userId} to ${shouldFreeze ? 'FREEZE' : 'UNFREEZE'} ---`);

    try {
        const newStatus = shouldFreeze ? 'Suspended' : 'Active';

        // Find and update the card status
        const card = await Card.findOneAndUpdate(
            { userId: userId },
            { status: newStatus },
            { new: true } // Return the updated document
        );

        if (!card) {
            return res.status(404).json({ success: false, message: 'Card not found.' });
        }

        console.log(`✅ Card status updated to: ${card.status}`);
        res.status(200).json({ 
            success: true, 
            message: `Card has been ${newStatus.toLowerCase()}.`,
            data: { isFrozen: card.status === 'Suspended' } 
        });

    } catch (error) {
        console.error('Error toggling card status:', error);
        res.status(500).json({ success: false, message: 'Server error while updating card status.' });
    }
});

// ------------------------------------------------------------------------------------------------
// --- API for GET TRANSFER TYPES BY CURRENCY (NEW) ---
// ------------------------------------------------------------------------------------------------
// 🚨 PROTECTED ROUTE
app.get('/api/client/transfer-types', verifyClientToken, async (req, res) => {
    const userId = req.user.id;
    console.log(`\n--- Received Request for Transfer Types for Client ID: ${userId} ---`);

    try {
        const user = await User.findById(userId).select('currency');

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const currency = user.currency.toUpperCase();

        const transferTypes = {
            'USD': [
                'Transfer between own accounts', 
                'ACH Transfer (Domestic)', 
                'Wire Transfer (Domestic)', 
                'International Wire Transfer'
            ],
            'GBP': [
                'Transfer between own accounts',
                'Faster Payments (UK)', 
                'BACS Transfer (UK)', 
                'SWIFT Transfer (International)'
            ],
            'EUR': [
                'Transfer between own accounts',
                'SEPA Credit Transfer (Eurozone)', 
                'SEPA Instant Credit Transfer', 
                'International SWIFT Transfer'
            ],
            'CAD': [
                'Transfer between own accounts',
                'Interac e-Transfer', 
                'EFT (Electronic Fund Transfer)', 
                'Wire Transfer (Domestic/International)'
            ],
            'AUD': [
                'Transfer between own accounts',
                'OSKO Payment (Fast)',
                'BPay (Bills)', 
                'International SWIFT Transfer'
            ]
        };
        
        const types = transferTypes[currency] || [
            'Transfer between own accounts',
            'Standard Bank Transfer', 
            'International Transfer'
        ];

        console.log(`✅ Transfer types fetched for currency: ${currency}.`);
        res.status(200).json({ success: true, currency: currency, transferTypes: types });

    } catch (error) {
        console.error('Error fetching transfer types:', error);
        res.status(500).json({ success: false, message: 'Server error while retrieving transfer types.' });
    }
});

// ----------------------------------------------------------------
// --- API for CLIENT SUBMISSION (Client-Side Check Deposit Form) ---
// ----------------------------------------------------------------
// 🚨 PROTECTED ROUTE (Requires client JWT token)
// NOTE: `upload.fields` handles two file uploads: 'imageFront' and 'imageBack'
app.post('/api/client/check-deposits', verifyClientToken, upload.fields([
    { name: 'imageFront', maxCount: 1 },
    { name: 'imageBack', maxCount: 1 }
]), async (req, res) => {
    console.log('\n--- Received Client Check Deposit Submission ---');
    
    // NOTE: req.user is available from verifyClientToken middleware
    const { id: userId, username } = req.user; 
    // FIX 1: Destructure the destinationAccountNumber sent by the client
    const { amount, currencyCode, destinationAccountNumber } = req.body; 
    const { imageFront, imageBack } = req.files;

    // 1. Basic Validation
    // FIX 2: Check for destinationAccountNumber in basic validation
    if (!amount || !currencyCode || !destinationAccountNumber || !imageFront || !imageBack || !imageFront[0] || !imageBack[0]) {
        // Cleanup uploaded files on failure
        if (imageFront && imageFront[0]) fs.unlinkSync(imageFront[0].path);
        if (imageBack && imageBack[0]) fs.unlinkSync(imageBack[0].path);
        return res.status(400).json({ success: false, message: 'Missing required fields (amount, currency, account number, or both check images).' });
    }
    
    // 2. Format Validation
    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0.01) {
        // Cleanup uploaded files
        fs.unlinkSync(imageFront[0].path);
        fs.unlinkSync(imageBack[0].path);
        return res.status(400).json({ success: false, message: 'Invalid deposit amount.' });
    }
    
    try {
        // 3. Generate Human-Readable Deposit ID
        // In a real app, this should be an atomic transaction to ensure uniqueness
        const lastDeposit = await CheckDeposit.findOne().sort({ createdAt: -1 });
        let nextDepositIdNum = 1000;
        if (lastDeposit && lastDeposit.depositId) {
            const lastNum = parseInt(lastDeposit.depositId.split('-')[1]);
            if (!isNaN(lastNum)) {
                nextDepositIdNum = lastNum + 1;
            }
        }
        const depositId = `DEP-${nextDepositIdNum}`;

        // 4. Create New Deposit Document
        const newDeposit = new CheckDeposit({
            depositId,
            userId,
            username, // Stored for faster lookup by admin
            amount: parsedAmount,
            currencyCode: currencyCode.toUpperCase(),
            destinationAccountNumber, // FIX 3: Include the destination account number
            imageFrontUrl: `/uploads/${imageFront[0].filename}`,
            imageBackUrl: `/uploads/${imageBack[0].filename}`,
            status: 'Pending' // Status must be capitalized to match schema enum
        });

        await newDeposit.save();

        console.log(`✅ New Check Deposit ${depositId} submitted by User ${userId}.`);
        res.status(201).json({ 
            success: true, 
            message: `Check deposit (${depositId}) for ${currencyCode} ${parsedAmount.toFixed(2)} submitted successfully. It is now Pending review.`,
            depositId: depositId
        });

    } catch (error) {
        console.error('Error submitting check deposit:', error);
        // Ensure files are cleaned up if DB save fails
        if (imageFront && imageFront[0]) fs.unlinkSync(imageFront[0].path);
        if (imageBack && imageBack[0]) fs.unlinkSync(imageBack[0].path);
        res.status(500).json({ success: false, message: 'Server error during deposit submission.' });
    }
});

// ------------------------------------------------------------
// --- Database Initialization Function (STAYS THE SAME) ---
// ------------------------------------------------------------
// This function is called by the main server logic (below)
async function populateInitialData() {
    // Since the User and Admin models are defined earlier, we can use them here.
    const AdminEmail = ADMIN_EMAIL; 
    const AdminPassword = ADMIN_PASSWORD;
    
    // 1. Check if the root Admin account exists
    const existingAdmin = await Admin.findOne({ email: AdminEmail }); // Assuming Admin model is defined/imported

    if (!existingAdmin) {
        console.log(`ℹ️ Root Admin account (${AdminEmail}) not found. Creating default admin...`);
        
        try {
            const hashedPassword = await bcrypt.hash(AdminPassword, SALT_ROUNDS);
            
            await Admin.create({
                fullName: 'Sunflower Union',
                email: AdminEmail,
                passwordHash: hashedPassword,
                role: 'BasicAdmin'
            });
            console.log('✅ Default Root Admin created successfully.');
        } catch (error) {
            console.error('❌ Failed to create default Root Admin:', error);
        }
    } else {
        console.log('ℹ️ Root Admin account already exists. Skipping creation.');
    }

    console.log('ℹ️ Initial data population function executed.'); 
    return true;
}

// ----------------------------------------------------------------------------------
// 🚀 EXPRESS ROUTING AND MIDDLEWARE DEFINITIONS (STAYS THE SAME)
// ----------------------------------------------------------------------------------

// Make the 'uploads' folder publicly accessible
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Serve static files from specific, known client-side directories.
// This prevents exposing sensitive files outside these folders.

// 1. Serve 'client' assets (e.g., /client/styles.css)
app.use('/client', express.static(path.join(__dirname, 'client')));

// 2. Serve 'admin' assets (e.g., /admin/dashboard.js)
app.use('/admin', express.static(path.join(__dirname, 'admin')));

// 3. Handle the main index.html file at the root URL
app.get('/', (req, res) => {
    // Load the confirmed public file (index.html) at the root URL
    res.sendFile(path.join(__dirname, 'index.html')); 
});

// ----------------------------------------------------------------------------------
// --- VERCEL COMPATIBLE SERVER STARTUP LOGIC (CRITICAL CHANGE) ---
// ----------------------------------------------------------------------------------

// This block is what Vercel expects for a standard Node.js server entry file.
// It initiates the database connection and starts the Express server.
async function startServer() {
    try {
        await mongoose.connect(MONGODB_URI);
        console.log('🔗 Database connection established successfully.');

        // Run the data population function immediately after connection
        await populateInitialData();

        // Start listening only in a local environment, Vercel handles the listener
        if (process.env.NODE_ENV !== 'production') {
            app.listen(PORT, () => {
                console.log(`🌐 Server running locally on http://localhost:${PORT}`);
            });
        }
        
    } catch (error) {
        console.error('❌ FATAL ERROR: Failed to connect to database or start server:', error);
        process.exit(1);
    }
}

// Execute the server start function
startServer();

// ----------------------------------------------------------------------------------
// --- VERCEL EXPORT (MINIMAL) ---
// ----------------------------------------------------------------------------------

// Only export the app itself for Vercel to correctly identify and wrap it 
// as a Serverless Function. This is often optional but good practice.
module.exports = app;