const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB (Make sure you have MongoDB running)
mongoose.connect('mongodb+srv://demo:demo@cluster0.hxofn2k.mongodb.net/?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const secretKey = 'suresh_project';

// Document Schema with Field Validations
const documentSchema = new mongoose.Schema({
  created_at: {
    type: String,
    required: true,
  },
  created_by: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  amount: {
    type: Number,
    required: true,
    min: 0, // Minimum value for amount (you can adjust this as needed)
  },
  contact_info: {
    type: String,
    required: true,
  },
  status: {
    type: String,
    enum: ['IN_PROGRESS', 'PAID', 'UN_PAID'], // Define allowed status values
    required: true,
  },
  customer_name: {
    type: String,
    required: true,
  },
});

const userSchema = new mongoose.Schema({
  user_name: {
    type: String,
    required: true,
    unique: true, // Ensure unique usernames
  },
  password: {
    type: String,
    required: true,
  },
  // Add more user-related fields as needed
});

// Create a User Model
const User = mongoose.model('suresh_user', userSchema);
const Document = mongoose.model('documents', documentSchema);

// Middleware for JWT authentication
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }

  console.log(token,"@@@@@@@@")

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      console.log(err)
      return res.status(401).json({ message: 'Unauthorized' });
    }

    req.user = decoded;
    next();
  });
};

// Middleware for handling validation errors
const handleValidationErrors = (err, req, res, next) => {
  if (err.name === 'ValidationError') {
    // Handle validation errors
    const validationErrors = {};
    for (const field in err.errors) {
      validationErrors[field] = err.errors[field].message;
    }
    res.status(400).json({ errors: validationErrors });
  } else {
    next(err);
  }
};

// Middleware for handling general errors
const handleGeneralErrors = (err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'An error occurred' });
};

app.use('/documents', verifyToken); // Apply JWT authentication middleware to document-related routes

// Add middleware for handling validation and general errors
app.use(handleValidationErrors);
app.use(handleGeneralErrors);

app.post(
  '/login',
  [
    // Validation middleware using express-validator
    body('user_name').notEmpty().isString().withMessage('Username is required'),
    body('password').notEmpty().isString().withMessage('Password is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { user_name, password } = req.body;

      // Find the user by user_name in the 'suresh_users' collection
      const user = await User.findOne({ user_name });

      if (!user) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }

      // Verify the password
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }

      // If the username and password are valid, you can generate a token or a session to manage user authentication.

      const token = jwt.sign({ user_name: user.user_name }, secretKey, { expiresIn: '1h' });

      res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred during login' });
    }
  }
);

app.post(
  '/register',
  [
    // Validation middleware using express-validator
    body('user_name').notEmpty().isString().withMessage('Username is required'),
    body('password')
      .notEmpty()
      .isString()
      .isLength({ min: 6 })
      .withMessage('Password is required and must be at least 6 characters long'),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { user_name, password } = req.body;

      // Check if the user already exists
      const existingUser = await User.findOne({ user_name });

      if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
      }

      // Hash the password before storing it
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create a new user
      const newUser = new User({
        user_name,
        password: hashedPassword,
        // Add more user-related fields as needed
      });

      await newUser.save();

      res.status(201).json({ message: 'Account created successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred during account registration' });
    }
  }
);

// Create a new document with validation
app.post('/documents', [
  // Validation middleware using express-validator
  body('created_at').notEmpty().isString().withMessage('Created at is required'),
  body('created_by').notEmpty().isString().withMessage('Created by is required'),
  body('description').notEmpty().isString().withMessage('Description is required'),
  body('amount').notEmpty().isNumeric().withMessage('Amount is required and must be a number'),
  body('contact_info').notEmpty().isString().withMessage('Contact info is required'),
  body('status')
    .notEmpty()
    .isString()
    .isIn(['IN_PROGRESS', 'PAID', 'UN_PAID'])
    .withMessage('Status is required and must be one of: Pending, Approved, Rejected'),
  body('customer_name').notEmpty().isString().withMessage('Customer name is required'),
], async (req, res) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { created_at, created_by, description, amount, contact_info, status, customer_name } = req.body;
    const newDocument = new Document({
      created_at,
      created_by,
      description,
      amount,
      contact_info,
      status,
      customer_name,
      // Add other document fields as needed
    });
    await newDocument.validate(); // Perform validation
    await newDocument.save();
    res.status(201).json({ message: 'Document created successfully' });
  } catch (error) {
    if (error.name === 'ValidationError') {
      // Handle validation errors
      const validationErrors = {};
      for (const field in error.errors) {
        validationErrors[field] = error.errors[field].message;
      }
      res.status(400).json({ errors: validationErrors });
    } else {
      console.error(error);
      res.status(500).json({ error: 'An error occurred while creating the document' });
    }
  }
});

app.get('/documents', async (req, res) => {
  try {
    const documents = await Document.find();
    res.status(200).json(documents);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while fetching documents' });
  }
});

app.get('/documents/:documentId', async (req, res) => {
  try {
    const documentId = req.params.documentId;
    const document = await Document.findById(documentId);
    if (!document) {
      return res.status(404).json({ message: 'Document not found' });
    }
    res.status(200).json(document);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while fetching the document' });
  }
});

app.put('/documents/:documentId', [
  // Validation middleware using express-validator
  body('created_at').notEmpty().isString().withMessage('Created at is required'),
  body('created_by').notEmpty().isString().withMessage('Created by is required'),
  body('description').notEmpty().isString().withMessage('Description is required'),
  body('amount').notEmpty().isNumeric().withMessage('Amount is required and must be a number'),
  body('contact_info').notEmpty().isString().withMessage('Contact info is required'),
  body('status')
    .notEmpty()
    .isString()
    .isIn(['Pending', 'Approved', 'Rejected'])
    .withMessage('Status is required and must be one of: Pending, Approved, Rejected'),
  body('customer_name').notEmpty().isString().withMessage('Customer name is required'),
], async (req, res) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const documentId = req.params.documentId;
    const updatedData = req.body;
    const document = await Document.findByIdAndUpdate(documentId, updatedData, {
      new: true,
      runValidators: true, // Run validators on update
    });
    if (!document) {
      return res.status(404).json({ message: 'Document not found' });
    }
    res.status(200).json(document);
  } catch (error) {
    if (error.name === 'ValidationError') {
      // Handle validation errors
      const validationErrors = {};
      for (const field in error.errors) {
        validationErrors[field] = error.errors[field].message;
      }
      res.status(400).json({ errors: validationErrors });
    } else {
      console.error(error);
      res.status(500).json({ error: 'An error occurred while updating the document' });
    }
  }
});

app.delete('/documents/:documentId', async (req, res) => {
  try {
    const documentId = req.params.documentId;
    const document = await Document.findByIdAndRemove(documentId);
    if (!document) {
      return res.status(404).json({ message: 'Document not found' });
    }
    res.status(200).json({ message: 'Document deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while deleting the document' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
