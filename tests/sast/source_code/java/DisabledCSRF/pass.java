class Connector {
    @javax.jws.WebMethod
    void connect(HttpServletRequest req){
        // http.csrf().disable(); // Compliant
    }
}
