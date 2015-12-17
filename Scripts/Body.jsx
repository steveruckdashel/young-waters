import React from "react";

export default React.createClass({
    render: function () {
        return (
          <div className="slds-grid">
            <div className="slds-col"><a href="/yahoo/auth/" className="slds-button slds-button--brand">Login with Yahoo</a></div>
            <div className="slds-col"><a href="/yahoo/users/games" className="slds-button slds-button--brand">Get User</a></div>
            <div className="slds-col"><a href="/yahoo/users/game/348" className="slds-button slds-button--brand">Get All Game Data</a></div>
          </div>
        );
    }
});