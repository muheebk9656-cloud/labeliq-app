const express = require('express');
const path = require('path');
const session = require('express-session');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Setup View Engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Core Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session Configuration
app.use(
  session({
    secret: 'labeliq-secret-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
  })
);

// In-Memory Database Simulation
const users = [
  { username: 'admin', password: 'admin123', role: 'consumer', name: 'Consumer User' },
  { 
    username: 'business_user', 
    password: 'admin123', 
    role: 'business', 
    name: 'SunJoy Rep',
    businessDetails: {
      name: 'SunJoy Foods Pvt. Ltd.',
      type: 'Manufacturer',
      address: 'Plot 45, Industrial Area, Sector 18, Gurugram, Haryana',
      email: 'contact@sunjoyfoods.com',
      phone: '+91 98765 43210',
      gstin: '06AAJCS1234A1ZX',
      manager: 'SunJoy Rep'
    }
  },
  { username: 'inspector', password: 'admin123', role: 'legal', name: 'Insp. R. K. Sharma', badge: 'LM-HAR-104' },
  { username: 'legal_admin', password: 'admin123', role: 'legal_admin', name: 'Directorate General' }
];

// RBAC Middleware
function checkPortalAuth(requiredRole) {
  return (req, res, next) => {
    if (!req.session || !req.session.user) {
      return res.redirect(`/signin?portal=${requiredRole}`);
    }
    if (requiredRole === 'legal' && req.session.user.role === 'legal_admin') {
      return next();
    }
    if (req.session.user.role !== requiredRole) {
      return res.status(403).render('unauthorized', {
        userRole: req.session.user.role,
        attemptedRole: requiredRole
      });
    }
    next();
  };
}

// Admin Clearance Middleware
function requireAdminClearance(req, res, next) {
  if (req.session && req.session.isAdminCleared) {
    return next();
  }
  res.redirect('/legal/admin/auth');
}

// -------------------------------------------------------------
// Authentication Routes
// -------------------------------------------------------------

app.get('/signin', (req, res) => {
  const portal = req.query.portal || 'consumer';
  res.render('signin', { error: null, portal });
});

app.post('/signin', (req, res) => {
  const { username, password, targetPortal } = req.body;
  const user = users.find(u => u.username === username && u.password === password);

  if (!user) {
    return res.render('signin', {
      error: 'Invalid credentials.',
      portal: targetPortal || 'consumer'
    });
  }

  if (targetPortal && user.role !== targetPortal && user.role !== 'legal_admin') {
    return res.render('signin', {
      error: `Access Denied: Account role is "${user.role.toUpperCase()}", but signing into "${targetPortal.toUpperCase()}".`,
      portal: targetPortal
    });
  }

  req.session.user = user;

  if (user.role === 'business') return res.redirect('/business');
  if (user.role === 'legal' || user.role === 'legal_admin') return res.redirect('/legal');
  return res.redirect('/');
});

app.get('/signup', (req, res) => {
  const portal = req.query.portal || 'consumer';
  res.render('signup', { error: null, portal });
});

app.post('/signup', (req, res) => {
  const { 
    username, 
    password, 
    confirmPassword, 
    portal,
    businessName,
    businessType,
    storeAddress,
    businessEmail,
    phoneNumber,
    gstin,
    managerName
  } = req.body;

  const targetPortal = portal || 'consumer';

  if (!username || !password) {
    return res.render('signup', { error: 'Username and password are required.', portal: targetPortal });
  }

  if (password !== confirmPassword) {
    return res.render('signup', { error: 'Passwords do not match.', portal: targetPortal });
  }

  if (users.find(u => u.username === username)) {
    return res.render('signup', { error: 'Username already registered.', portal: targetPortal });
  }

  const newUser = {
    username,
    password,
    role: targetPortal,
    name: managerName || username,
    businessDetails: targetPortal === 'business' ? {
      name: businessName,
      type: businessType,
      address: storeAddress,
      email: businessEmail,
      phone: phoneNumber,
      gstin: gstin || 'Not Provided',
      manager: managerName
    } : null
  };

  users.push(newUser);
  req.session.user = newUser;

  if (targetPortal === 'business') return res.redirect('/business');
  if (targetPortal === 'legal') return res.redirect('/legal');
  return res.redirect('/');
});

app.get('/auth/google/mock', (req, res) => {
  let googleUser = users.find(u => u.username === 'google_consumer');
  if (!googleUser) {
    googleUser = { username: 'google_consumer', password: 'oauth_dummy_password', role: 'consumer', name: 'Google Verified' };
    users.push(googleUser);
  }
  req.session.user = googleUser;
  res.redirect('/');
});

app.get('/signout', (req, res) => {
  const targetPortal = req.query.portal || 'consumer';
  req.session.destroy(() => {
    res.redirect(`/signin?portal=${targetPortal}`);
  });
});

// -------------------------------------------------------------
// Directorate Admin Authorization & Officer Registry
// -------------------------------------------------------------

app.get(['/legal/admin/auth', '/admin/auth'], (req, res) => {
  res.render('admin_auth', { error: null });
});

app.post(['/legal/admin/auth', '/admin/auth'], (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);

  if (user && user.role === 'legal_admin') {
    req.session.isAdminCleared = true;
    req.session.user = user;
    return res.redirect('/legal/admin/register');
  }

  res.render('admin_auth', { 
    error: 'Access Denied: Invalid administrator credentials or insufficient clearance.' 
  });
});

app.get('/legal/admin/register', requireAdminClearance, (req, res) => {
  const officers = users.filter(u => u.role === 'legal');
  res.render('register_officer', {
    officers,
    success: req.query.success || null,
    error: null
  });
});

app.post('/legal/admin/register', requireAdminClearance, (req, res) => {
  const { officerName, badgeNumber, username, password } = req.body;
  const officers = users.filter(u => u.role === 'legal');

  if (!officerName || !badgeNumber || !username || !password) {
    return res.render('register_officer', { officers, error: 'All fields are required.', success: null });
  }

  if (users.find(u => u.username === username)) {
    return res.render('register_officer', { officers, error: 'Username already registered.', success: null });
  }

  users.push({
    username,
    password,
    role: 'legal',
    name: officerName,
    badge: badgeNumber
  });

  res.redirect('/legal/admin/register?success=Officer+registered+successfully');
});

// -------------------------------------------------------------
// Verification Document Viewer
// -------------------------------------------------------------

app.get('/verification', (req, res) => {
  const filePath = path.join(__dirname, 'public', 'verification_rules.txt');
  fs.readFile(filePath, 'utf8', (err, textContent) => {
    if (err) {
      return res.status(500).send('Unable to load verification document. Ensure public/verification_rules.txt exists.');
    }
    res.render('verification_view', { content: textContent });
  });
});

// -------------------------------------------------------------
// Dashboards
// -------------------------------------------------------------

// 1. Consumer Portal
app.get('/', checkPortalAuth('consumer'), (req, res) => {
  const consumerData = {
    brandName: 'LabelIQ',
    currentUser: req.session.user.username,
    navLinks: ['Product', 'Rule Engine', 'Verification'],
    categories: ['All', 'Food', 'Cosmetics', 'Medical', 'Household', 'Textiles'],
    steps: [
      { number: '01', title: 'Upload label', description: 'Drag a photo of any packaged commodity — front or back label.' },
      { number: '02', title: 'AI extraction', description: 'OCR reads every declaration. The rule engine maps each field to LM(PC) Rules, 2011.' },
      { number: '03', title: 'Instant report', description: 'Each item is flagged Pass, Fail, or Needs Review with statutory citation and correction advice.' }
    ]
  };
  res.render('index', { data: consumerData });
});

// 2. Business Portal
app.get('/business', checkPortalAuth('business'), (req, res) => {
  const user = req.session.user;
  const businessDetails = user.businessDetails || {};

  const businessData = {
    company: {
      name: businessDetails.name || 'SunJoy Foods',
      role: businessDetails.type || 'Manufacturer',
      gstin: businessDetails.gstin || '06AAJCS1234A1ZX'
    },
    currentUser: user.username,
    metrics: { 
      scannedCount: 7, 
      scannedPeriod: 'All time', 
      compliantRate: '43%', 
      compliantSubtitle: '3 of 7 pass', 
      pendingReview: 1, 
      pendingSubtitle: 'Awaiting scan', 
      violationsCount: 6, 
      violationsSubtitle: 'Across all SKUs' 
    },
    products: [
      { name: 'SunJoy Fine Atta 1 kg', category: 'Food', sku: 'SJF-WW-1KG', type: 'Retail', destination: 'Domestic', lastChecked: '16 Sep 2025', status: 'Non-Compliant', flagCount: '2x' },
      { name: 'SunJoy Fine Atta 5 kg', category: 'Food', sku: 'SJF-WW-5KG', type: 'Retail', destination: 'Domestic', lastChecked: '15 Sep 2025', status: 'Compliant', flagCount: null },
      { name: 'SunJoy Maida 1 kg', category: 'Food', sku: 'SJF-MD-1KG', type: 'Retail', destination: 'Domestic', lastChecked: '14 Sep 2025', status: 'Needs Review', flagCount: '1x' },
      { name: 'SunJoy Suji Premium 500 g', category: 'Food', sku: 'SJF-SJ-500G', type: 'Retail', destination: 'Export', lastChecked: '13 Sep 2025', status: 'Compliant', flagCount: null },
      { name: 'SunJoy Besan 500 g', category: 'Food', sku: 'SJF-BS-500G', type: 'Retail', destination: 'Domestic', lastChecked: '12 Sep 2025', status: 'Non-Compliant', flagCount: '3x' },
      { name: 'SunJoy Daliya 500 g', category: 'Food', sku: 'SJF-DL-500G', type: 'Retail', destination: 'Domestic', lastChecked: '11 Sep 2025', status: 'Compliant', flagCount: null },
      { name: 'SunJoy Atta 10 kg Bulk', category: 'Food', sku: 'SJF-WW-10KG', type: 'Bulk', destination: 'B2B', lastChecked: '10 Sep 2025', status: 'Pending', flagCount: null }
    ]
  };
  res.render('business', { data: businessData });
});

// 3. Legal Authority Portal
app.get('/legal', checkPortalAuth('legal'), (req, res) => {
  const legalData = {
    officer: {
      initials: 'RK',
      name: req.session.user.name || 'Insp. R. K. Sharma',
      role: req.session.user.badge ? `Enforcement Officer (${req.session.user.badge})` : 'Enforcement Officer',
      region: 'Legal Metrology Directorate — Haryana Region'
    },
    currentUser: req.session.user.username,
    metrics: { totalCases: 6, awaitingAction: 1, investigating: 2, verifiedViolations: 2 },
    filters: [
      { label: 'All (6)', active: true },
      { label: 'New (1)', active: false },
      { label: 'Investigating', active: false },
      { label: 'Verified', active: false },
      { label: 'Dismissed', active: false }
    ],
    cases: [
      { id: 'CAS-2025-09-1842', title: 'NutriGold Protein Bar 30g', status: 'New', statusStyle: 'bg-[#eef2ff] text-[#4f46e5]', dotColor: 'bg-red-500', date: '16 Sep 2025', source: 'Consumer — Priya Mehta · Food', rules: ['Rule 6(1)(g)', 'Rule 6(1)(h)'] },
      { id: 'CAS-2025-09-1841', title: 'GlowPure Face Cream 50g', status: 'Under Investigation', statusStyle: 'bg-[#fffbeb] text-[#b45309]', dotColor: 'bg-red-500', date: '15 Sep 2025', source: 'Field — Insp. R. K. Sharma · Cosmetics', rules: ['Rule 6(1)(d)', 'Rule 13'] },
      { id: 'CAS-2025-09-1839', title: 'CleanMax Detergent 1 kg', status: 'Under Investigation', statusStyle: 'bg-[#fffbeb] text-[#b45309]', dotColor: 'bg-amber-500', date: '14 Sep 2025', source: 'Industry — RetailFirst Ltd. · Household', rules: ['Rule 10', 'Rule 6(1)(c)'] },
      { id: 'CAS-2025-09-1835', title: 'HealWell Antiseptic 200 ml', status: 'Verified Violation', statusStyle: 'bg-[#fef2f2] text-[#dc2626]', dotColor: 'bg-red-500', date: '12 Sep 2025', source: 'Consumer — Rajesh Kumar · Medical', rules: ['Rule 6(1)(e)'] },
      { id: 'CAS-2025-09-1831', title: 'SunJoy Fine Atta 1 kg', status: 'Verified Violation', statusStyle: 'bg-[#fef2f2] text-[#dc2626]', dotColor: 'bg-amber-500', date: '10 Sep 2025', source: 'Field — Insp. S. Patel · Food', rules: ['Rule 6(1)(g)', 'Rule 6(1)(h)', 'Rule 6(1)(i)'] },
      { id: 'CAS-2025-09-1824', title: 'FeatherSoft Bedsheets', status: 'Dismissed', statusStyle: 'bg-[#f1f5f9] text-[#64748b]', dotColor: 'bg-slate-400', date: '7 Sep 2025', source: 'Consumer — Ananya Singh · Textile', rules: ['Rule 6(2)'] }
    ],
    queueMetrics: { totalCases: 5, newCases: 2 },
    queueCases: [
      { caseId: 'CAS-2026-081', commodityName: 'NutriGold Protein Bar 30g', violation: 'Missing MRP', priority: 'High', date: 'Today' },
      { caseId: 'CAS-2026-079', commodityName: 'SunJoy Fine Atta 1 kg', violation: 'Net Quantity Undersized', priority: 'High', date: 'Today' },
      { caseId: 'CAS-2026-074', commodityName: 'CleanMax Detergent 1 kg', violation: 'Manufacturer Address Incomplete', priority: 'Medium', date: 'Yesterday' },
      { caseId: 'CAS-2026-068', commodityName: 'GlowPure Face Cream 50g', violation: 'Missing Expiry Date', priority: 'High', date: '14 Sep 2026' },
      { caseId: 'CAS-2026-061', commodityName: 'FeatherSoft Bedsheet Cotton', violation: 'Font Size Rule 6(2)', priority: 'Medium', date: '12 Sep 2026' }
    ],
    inspectionMetrics: {
      total: 12,
      inProgress: 3,
      completed: 7,
      nonCompliant: 2
    },
    inspections: [
      { id: 'INS-2026-101', product: 'SunJoy Fine Atta 1 kg', manufacturer: 'SunJoy Foods Pvt Ltd', inspector: 'Insp. R. K. Sharma', date: '16 Sep 2026', status: 'completed' },
      { id: 'INS-2026-102', product: 'NutriGold Protein Bar 30g', manufacturer: 'Apex Nutrition Ltd', inspector: 'Insp. S. Patel', date: '16 Sep 2026', status: 'non_compliant' },
      { id: 'INS-2026-103', product: 'CleanMax Detergent 1 kg', manufacturer: 'RetailFirst Brands', inspector: 'Insp. R. K. Sharma', date: '15 Sep 2026', status: 'in_progress' },
      { id: 'INS-2026-104', product: 'GlowPure Cream 50g', manufacturer: 'PureSkin Organics', inspector: 'Insp. A. Verma', date: '14 Sep 2026', status: 'completed' },
      { id: 'INS-2026-105', product: 'FeatherSoft Bedding Set', manufacturer: 'LoomCraft India', inspector: 'Insp. S. Patel', date: '12 Sep 2026', status: 'non_compliant' }
    ]
  };

  res.render('legal', { data: legalData });
});

// 4. Rule Management Route (Resolves Cannot GET /legal/rules)
app.get('/legal/rules', checkPortalAuth('legal'), (req, res) => {
  const legalData = {
    officer: {
      initials: 'RK',
      name: req.session.user.name || 'Insp. R. K. Sharma',
      role: req.session.user.badge ? `Enforcement Officer (${req.session.user.badge})` : 'Enforcement Officer',
      region: 'Legal Metrology Directorate'
    },
    currentUser: req.session.user.username
  };
  res.render('rule_management', { data: legalData });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
// Artwork Pre-Check Modal / Dedicated Screen
app.get('/business/artwork-check', checkPortalAuth('business'), (req, res) => {
  res.render('artwork_check');
});

// Post submission handler for pre-check
app.post('/business/artwork-check', checkPortalAuth('business'), (req, res) => {
  const { category, targetMarket } = req.body;
  // Redirect back with notification query flag
  res.redirect('/business?precheck=success');
});
// Process Label / Commodity Scan
app.post('/scan/process', (req, res) => {
  const { sourcePortal, commodityCategory } = req.body;

  if (sourcePortal === 'legal') {
    return res.redirect('/legal?scanned=success');
  }
  res.redirect('/business?scanned=success');
});
// Correction History Route for Business Portal
app.get('/business/corrections', checkPortalAuth('business'), (req, res) => {
  const user = req.session.user;
  const businessDetails = user.businessDetails || {};

  const correctionData = {
    company: {
      name: businessDetails.name || 'SunJoy Foods',
      role: businessDetails.type || 'Manufacturer',
      gstin: businessDetails.gstin || '06AAJCS1234A1ZX'
    },
    currentUser: user.username,
    metrics: {
      totalCorrections: 4,
      resolvedCount: 3,
      pendingReviewCount: 1
    },
    history: [
      {
        revisionId: 'REV-2026-041',
        commodityName: 'SunJoy Fine Atta 1 kg',
        sku: 'SJF-WW-1KG',
        ruleCitation: 'Rule 6(1)(e)',
        violationType: 'Missing Inclusive of all taxes on MRP',
        previousValue: '₹ 45.00',
        correctedValue: '₹ 45.00 (Incl. of all taxes)',
        timestamp: '16 Sep 2026, 11:20 AM',
        status: 'Resolved'
      },
      {
        revisionId: 'REV-2026-038',
        commodityName: 'SunJoy Besan 500 g',
        sku: 'SJF-BS-500G',
        ruleCitation: 'Rule 7',
        violationType: 'Net quantity font height below 4mm',
        previousValue: 'Font height: 2.2 mm',
        correctedValue: 'Font height: 4.2 mm (Standard compliant)',
        timestamp: '15 Sep 2026, 04:45 PM',
        status: 'Resolved'
      },
      {
        revisionId: 'REV-2026-029',
        commodityName: 'SunJoy Maida 1 kg',
        sku: 'SJF-MD-1KG',
        ruleCitation: 'Rule 10',
        violationType: 'Manufacturer consumer care email omitted',
        previousValue: 'Only postal pin code printed',
        correctedValue: 'support@sunjoyfoods.com + Helpline added',
        timestamp: '14 Sep 2026, 02:15 PM',
        status: 'Resolved'
      },
      {
        revisionId: 'REV-2026-012',
        commodityName: 'SunJoy Atta 10 kg Bulk',
        sku: 'SJF-WW-10KG',
        ruleCitation: 'Rule 24',
        violationType: 'Wholesale package total declaration',
        previousValue: 'Missing retail pack count specification',
        correctedValue: 'Artwork updated to contain 10 x 1 kg sub-packs',
        timestamp: '13 Sep 2026, 09:10 AM',
        status: 'Pending Review'
      }
    ]
  };

  res.render('correction_history', { data: correctionData });
});