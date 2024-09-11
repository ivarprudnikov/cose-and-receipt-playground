it('loads the homepage', () => {
    cy.visit('/')
    cy.contains('COSE signatures').should('be.visible')
})