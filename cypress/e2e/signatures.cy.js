describe('signature tests', () => {

  it('create a signature', function() {
    
    cy.visit('/')

    let sigBody
    let sigHex
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
    }).as('sig')

    cy.get('#sign').within(() => {
      cy.get('[aria-controls="payloadTextSection"]').should('be.visible').click()
      cy.get('#payload', { timeout: 1000 }).type('foobar')
      cy.get('input[name="headerkey"]').first().type('3')
      cy.get('input[name="headerval"]').first().type('text/plain')
      cy.get('.btn-primary').should('be.visible').click()
    })

    cy.wait('@sig')
    cy.location('pathname').should('be.equal', '/')
      .then(() => {
        cy.wrap(sigBody.byteLength).should('be.greaterThan',0)
        cy.wrap(sigHex).should('be.a', 'string').should('not.be.empty')
      })
    
  })

})