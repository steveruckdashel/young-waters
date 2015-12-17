import React from "react";

export default React.createClass({
    render: function () {
        return (
            <div className="slds-col">
                <header className="menu">
                    <ul className="slds-list--horizontal">
                        <li className="slds-list__item">Properties</li>
                        <li className="slds-list__item">Contacts</li>
                        <li className="slds-list__item">Brokers</li>
                    </ul>
                </header>
            </div>
        );
    }
});