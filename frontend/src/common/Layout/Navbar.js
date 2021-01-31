import React, { useState } from 'react';
import { Button } from 'react-bootstrap';
import ReactNav from 'react-bootstrap/Nav';
import ReactNavbar from 'react-bootstrap/Navbar';
import './Navbar.css';
import { request, getUUID, HOST } from '../utils.js';

function Navbar(props) {
    const [isAuth, setIsAuth] = useState(null);
    const handleAuth = (res) => {
        if (res.status !== 200) {
            setIsAuth(false);
        } else {
            setIsAuth(true);
        }
    };

    if (isAuth === null) {
        request('GET', `http://${HOST}:81/api/posts/0`, {})
            .then(handleAuth)
            .catch(handleAuth)
        ;
    }

    var navComponents;
    if (isAuth) {
        navComponents = (<>
            <ReactNav.Link href="/profile">Profile</ReactNav.Link>
            <ReactNav.Link href="/logout">Log Out</ReactNav.Link>
        </>);
    } else {
        navComponents = (<>
            <ReactNav.Link href="/signin">Sign In</ReactNav.Link>
            <ReactNav.Link href="/signup">Sign Up</ReactNav.Link>
        </>);
    }

    return (
        <ReactNavbar bg="light" variant="light">
            <ReactNavbar.Brand href="/">BearChat</ReactNavbar.Brand>
            <ReactNav className="mr-auto">
                {navComponents}
            </ReactNav>
        </ReactNavbar>
    );
}

export default Navbar;
