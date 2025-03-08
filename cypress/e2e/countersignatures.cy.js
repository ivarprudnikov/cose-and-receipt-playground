describe('countersignature tests', () => {
  var sigBody, sigHex = null
  before(function () {
    cy.visit('/')

    // Intercept and store the signature for later
    cy.intercept({
      pathname: '/signature/create',
    }, (req) => {
      req.reply((res) => {
        sigBody = res.body
        sigHex = res.headers['x-signature-hex']
      })
    }).as('createResponse')

    cy.get('#sign').within(() => {
      cy.get('[aria-controls="payloadTextSection"]').should('be.visible').click()
      cy.get('#payload', { timeout: 1000 }).type('hello world')
      cy.get('#issuertype').select('didx509')
      cy.get('input[name="headerkey"]').first().type('3')
      cy.get('input[name="headerval"]').first().type('application/json')
      cy.get('.btn-primary').should('be.visible').click()
    })

    cy.wait('@createResponse').then(() => {
      cy.wrap(sigHex).should('be.a', 'string').should('not.be.empty')
      cy.wrap(sigBody).should('not.be.undefined')
      cy.wrap(sigBody?.byteLength).should('be.greaterThan', 0)
    })
  })

  it('countersign using standalone receipt and verify', function () {
    cy.visit('/')
    let receiptBody, receiptHex
    cy.intercept({
      pathname: '/receipt/create',
    }, (req) => {
      req.reply((res) => {
        receiptBody = res.body
        receiptHex = res.headers['x-receipt-hex']
        // redirect the browser back to the original page
        res.headers.location = '/'
        res.send(302)
      })
    }).as('receiptResponse');

    cy.get('#countersign').within(() => {
      cy.get('[aria-controls="receiptSigHexSection"]').should('be.visible').click()
      cy.get('#receiptSigHex', { timeout: 1000 }).type(sigHex, { delay: 0 })
      cy.get('#receiptType').select('standalone')
      cy.get('.btn-primary').should('be.visible').click()
    });
    cy.wait('@receiptResponse');

    cy.location('pathname').should('be.equal', '/')
      .then(() => {
        cy.wrap(receiptBody.byteLength).should('be.greaterThan', 0)
        cy.wrap(receiptHex).should('be.a', 'string').should('not.be.empty')
      });

    let receiptVerifyBody
    cy.intercept({
      pathname: '/receipt/verify',
    }, (req) => {
      req.reply((res) => {
        receiptVerifyBody = res.body
        res.headers.location = '/'
        res.send(302)
      })
    }).as('receiptVerifyResponse');

    cy.get('#receipt-verify-form').within(() => {
      cy.get('[aria-controls="receiptVerifySigHexSection"]').should('be.visible').click()
      cy.get('#receiptVerifySigHex', { timeout: 1000 }).type(sigHex, { delay: 0 })
      cy.get('[aria-controls="receiptVerifyHexSection"]').should('be.visible').click()
      cy.get('#receiptVerifyHex', { timeout: 1000 }).type(receiptHex, { delay: 0 })
      cy.get('.btn-primary').should('be.visible').click()
    });
    cy.wait('@receiptVerifyResponse').then(() => {
      cy.wrap(receiptVerifyBody).should('be.an', 'object')
      cy.wrap(receiptVerifyBody).should('have.property', 'valid')
      cy.wrap(receiptVerifyBody.valid).should('be.true')
    });
  })

  it('countersign using embedded receipt and verify', function () {
    cy.visit('/')
    let receiptBody, receiptHex
    cy.intercept({
      pathname: '/receipt/create',
    }, (req) => {
      req.reply((res) => {
        receiptBody = res.body
        receiptHex = res.headers['x-receipt-hex']
        // redirect the browser back to the original page
        res.headers.location = '/'
        res.send(302)
      })
    }).as('receiptResponse');

    cy.get('#countersign').within(() => {
      cy.get('[aria-controls="receiptSigHexSection"]').should('be.visible').click()
      cy.get('#receiptSigHex', { timeout: 1000 }).type(sigHex, { delay: 0 })
      cy.get('#receiptType').select('embedded')
      cy.get('.btn-primary').should('be.visible').click()
    });
    cy.wait('@receiptResponse');

    cy.location('pathname').should('be.equal', '/')
      .then(() => {
        cy.wrap(receiptBody.byteLength).should('be.greaterThan', 0)
        cy.wrap(receiptHex).should('be.a', 'string').should('not.be.empty')
      });

    let receiptVerifyBody
    cy.intercept({
      pathname: '/receipt/verify',
    }, (req) => {
      req.reply((res) => {
        receiptVerifyBody = res.body
        res.headers.location = '/'
        res.send(302)
      })
    }).as('receiptVerifyResponse');

    cy.get('#receipt-verify-form').within(() => {
      cy.get('[aria-controls="receiptVerifySigHexSection"]').should('be.visible').click()
      cy.get('#receiptVerifySigHex', { timeout: 1000 }).type(receiptHex, { delay: 0 })
      cy.get('.btn-primary').should('be.visible').click()
    });
    cy.wait('@receiptVerifyResponse').then(() => {
      cy.wrap(receiptVerifyBody).should('be.an', 'object')
      cy.wrap(receiptVerifyBody).should('have.property', 'valid')
      cy.wrap(receiptVerifyBody.valid).should('be.true')
    });
  })
})