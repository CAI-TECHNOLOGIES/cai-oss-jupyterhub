import React, { useEffect } from "react";
import ReactDOM from "react-dom";
import { Provider } from "react-redux";
import { createStore } from "redux";
import { initialState, reducers } from "./Store";
import { jhapiRequest } from "./util/jhapiUtil";
import withAPI from "./util/withAPI";
import { HashRouter, Switch, Route } from "react-router-dom";

import ServerDashboard from "./components/ServerDashboard/ServerDashboard";
import Groups from "./components/Groups/Groups";
import GroupEdit from "./components/GroupEdit/GroupEdit";
import CreateGroup from "./components/CreateGroup/CreateGroup";
import AddUser from "./components/AddUser/AddUser";
import EditUser from "./components/EditUser/EditUser";

import "./style/root.css";

const store = createStore(reducers, initialState);

const App = () => {
  useEffect(() => {
    let { limit, user_page, groups_page } = initialState;
    jhapiRequest(`/users?offset=${user_page * limit}&limit=${limit}`, "GET")
      .then((data) => data.json())
      .then((data) =>
        store.dispatch({ type: "USER_PAGE", value: { data: data, page: 0 } })
      )
      .catch((err) => console.log(err));

    jhapiRequest(`/groups?offset=${groups_page * limit}&limit=${limit}`, "GET")
      .then((data) => data.json())
      .then((data) =>
        store.dispatch({ type: "GROUPS_PAGE", value: { data: data, page: 0 } })
      )
      .catch((err) => console.log(err));
  });

  return (
    <div className="resets">
      <Provider store={store}>
        <HashRouter>
          <Switch>
            <Route
              exact
              path="/"
              component={<ServerDashboard apis={withAPI} />}
            />
            <Route exact path="/groups" component={compose(withAPI)(Groups)} />
            <Route
              exact
              path="/group-edit"
              component={<GroupEdit apis={withAPI} />}
            />
            <Route
              exact
              path="/create-group"
              component={<CreateGroup apis={withAPI} />}
            />
            <Route
              exact
              path="/add-users"
              component={<AddUser apis={withAPI} />}
            />
            <Route
              exact
              path="/edit-user"
              component={<EditUser apis={withAPI} />}
            />
          </Switch>
        </HashRouter>
      </Provider>
    </div>
  );
};

ReactDOM.render(<App />, document.getElementById("react-admin-hook"));
