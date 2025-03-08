describe('signature tests', () => {

  it('create did:x509 signature and verify it', function () {

    cy.visit('/')

    let sigBody
    let sigHex
    // Intercept and store the signature for later
    cy.intercept({
      pathname: '/signature/create',
    }, (req) => {
      req.reply((res) => {
        sigBody = res.body
        sigHex = res.headers['x-signature-hex']
        // redirect the browser back to the original page
        res.headers.location = '/'
        res.send(302)
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

    cy.wait('@createResponse')
    cy.location('pathname').should('be.equal', '/')
      .then(() => {
        cy.wrap(sigBody.byteLength).should('be.greaterThan', 0)
        cy.wrap(sigHex).should('be.a', 'string').should('not.be.empty')
        cy.log('signature hex:', sigHex)
      });

    let verifyBody
    cy.intercept({
      pathname: '/signature/verify',
    }, (req) => {
      req.reply((res) => {
        verifyBody = res.body
        // redirect the browser back to the original page
        res.headers.location = '/'
        res.send(302)
      })
    }).as('verifyResponse');

    cy.get('#verify').within(() => {
      cy.get('[aria-controls="verifySigHexSection"]').should('be.visible').click()
      cy.get('#verifySigHex', { timeout: 1000 }).type(sigHex, { delay: 0 })
      cy.get('.btn-primary').should('be.visible').click()
    });
    cy.wait('@verifyResponse');

    cy.location('pathname').should('be.equal', '/')
      .then(() => {
        cy.wrap(verifyBody).should('be.an', 'object')
        cy.wrap(verifyBody).should('have.property', 'valid')
        cy.wrap(verifyBody.valid).should('be.true')
      });
  })

  it('create did:web signature and attempt to verify it which will fail', function () {

    cy.visit('/')

    let sigBody
    let sigHex
    // Intercept and store the signature for later
    cy.intercept({
      pathname: '/signature/create',
    }, (req) => {
      req.reply((res) => {
        sigBody = res.body
        sigHex = res.headers['x-signature-hex']
        // redirect the browser back to the original page
        res.headers.location = '/'
        res.send(302)
      })
    }).as('createResponse')

    cy.get('#sign').within(() => {
      cy.get('[aria-controls="payloadTextSection"]').should('be.visible').click()
      cy.get('#payload', { timeout: 1000 }).type('hello world')
      cy.get('#issuertype').select('did:web', { force: true })
      cy.get('input[name="headerkey"]').first().type('3')
      cy.get('input[name="headerval"]').first().type('application/json')
      cy.get('.btn-primary').should('be.visible').click()
    })

    cy.wait('@createResponse')
    cy.location('pathname').should('be.equal', '/')
      .then(() => {
        cy.wrap(sigBody.byteLength).should('be.greaterThan', 0)
        cy.wrap(sigHex).should('be.a', 'string').should('not.be.empty')
        cy.log('signature hex:', sigHex)
      });

    let verifyBody
    cy.intercept({
      pathname: '/signature/verify',
    }, (req) => {
      req.reply((res) => {
        verifyBody = res.body
        // redirect the browser back to the original page
        res.headers.location = '/'
        res.send(302)
      })
    }).as('verifyResponse');

    cy.get('#verify').within(() => {
      cy.get('[aria-controls="verifySigHexSection"]').should('be.visible').click()
      cy.get('#verifySigHex', { timeout: 1000 }).type(sigHex, { delay: 0 })
      cy.get('.btn-primary').should('be.visible').click()
    });
    cy.wait('@verifyResponse');

    cy.location('pathname').should('be.equal', '/')
      .then(() => {
        cy.wrap(verifyBody).should('be.an', 'object')
        cy.wrap(verifyBody).should('have.property', 'error')
        cy.wrap(verifyBody.error).should('contain', 'failed to resolve public key')
        cy.wrap(verifyBody.error).should('contain', 'https://localhost:8080/.well-known/did.json')
      });
  })
})